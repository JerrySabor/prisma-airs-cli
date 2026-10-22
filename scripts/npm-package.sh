#!/usr/bin/env bash
# Stages the npm packages of a release from its tarballs: the launcher package
# @cdot65/prisma-airs-cli@<version> (npm/) and one platform version of the same package
# per release target (<version>-darwin-arm64, <version>-linux-x64, <version>-linux-arm64),
# each holding exactly that target's released airs binary. docs/RELEASING.md §7 and
# DESIGN §21.16 describe the layout. usage() below holds the usage text (--help prints
# it, and every exit-2 refusal prints it on stderr).
#
# The tarballs are checked against SHA256SUMS first. Nothing is published: the output is
# the package directories and their `npm pack` tarballs. A refusal writes nothing; a
# failure removes what this run wrote.
set -Eeuo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="@cdot65/prisma-airs-cli"
PKG="airs-cli"
# <npm platform>=<rust target>, in the order the platform versions are published.
PLATFORMS=(darwin-arm64=aarch64-apple-darwin linux-x64=x86_64-unknown-linux-musl linux-arm64=aarch64-unknown-linux-musl)
ENTRIES=(airs airs-cli airs-cli-rs README.md LICENSE NOTICE)

usage() {
  cat <<'USAGE'
  scripts/npm-package.sh [--dist <dir>] [--output <dir>] [--verify-signature] <version>

  <version>            the release version (e.g. 8.0.0, no leading v)
  --dist <dir>         the release assets: SHA256SUMS and the three
                       airs-cli-<version>-<target>.tar.gz (default target/dist/<version>)
  --output <dir>       the staging directory; it must be absent or empty
                       (default target/npm/<version>)
  --verify-signature   run codesign --verify --strict on the darwin-arm64 binary (macOS)

  It writes <output>/packages/<platform>/ and <output>/packages/main/, their npm pack
  tarballs in <output>, and <output>/SHA256SUMS. It never publishes.
USAGE
}

usage_error() {
  echo "npm-package: $*" >&2
  usage >&2
  exit 2
}

die() {
  echo "npm-package: $*" >&2
  exit 1
}

# --- arguments --------------------------------------------------------------------

dist=""
output=""
verify_signature=0
positional=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --dist | --output)
      if [ "$#" -lt 2 ] || [ -z "$2" ] || [[ "$2" == -* ]]; then
        usage_error "$1 needs a directory"
      fi
      if [ "$1" = --dist ]; then
        [ -z "$dist" ] || usage_error "--dist given more than once"
        dist="$2"
      else
        [ -z "$output" ] || usage_error "--output given more than once"
        output="$2"
      fi
      shift 2
      ;;
    --verify-signature)
      [ "$verify_signature" -eq 0 ] || usage_error "--verify-signature given more than once"
      verify_signature=1
      shift
      ;;
    -?*)
      usage_error "unknown option: $1"
      ;;
    *)
      positional+=("$1")
      shift
      ;;
  esac
done
[ "${#positional[@]}" -eq 1 ] || usage_error "needs exactly one version"
version="${positional[0]}"
[ -n "$version" ] || usage_error "the <version> argument is empty"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
  || usage_error "'$version' is not a version like 8.0.0 (no leading v)"
dist="${dist:-$ROOT/target/dist/$version}"
output="${output:-$ROOT/target/npm/$version}"

# --- preconditions: nothing is written before every one holds ---------------------

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH"
}
need node
need npm
need tar
if command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$@"; }
else
  need sha256sum
  sha256() { sha256sum "$@"; }
fi
if [ "$verify_signature" -eq 1 ]; then
  command -v codesign >/dev/null 2>&1 || die "codesign is required for --verify-signature"
fi
[ -d "$dist" ] || die "$dist is not a directory"
[ -f "$dist/SHA256SUMS" ] || die "$dist/SHA256SUMS is missing"
if [ -e "$output" ] || [ -L "$output" ]; then
  [ -d "$output" ] && [ ! -L "$output" ] || die "$output exists and is not a directory"
  [ -z "$(ls -A "$output")" ] || die "$output exists and is not empty"
fi
for file in npm/package.json npm/bin/airs.js npm/lib/launcher.js npm/README.md LICENSE NOTICE; do
  [ -f "$ROOT/$file" ] || die "$ROOT/$file is missing"
done

# SHA256SUMS lists exactly the three tarballs, and each matches.
expected_tarballs=""
for spec in "${PLATFORMS[@]}"; do
  expected_tarballs+="$PKG-$version-${spec#*=}.tar.gz"$'\n'
done
listed="$(awk '{ print $2 }' "$dist/SHA256SUMS" | sed 's/^\*//' | sort)"
[ "$listed" = "$(printf '%s' "$expected_tarballs" | sort)" ] \
  || die "$dist/SHA256SUMS does not list exactly the three $PKG-$version-<target>.tar.gz"
(cd "$dist" && sha256 -c --quiet SHA256SUMS) >/dev/null 2>&1 \
  || die "the tarballs in $dist do not match SHA256SUMS"

# --- cleanup: a failure leaves nothing this run wrote -----------------------------

created_output=0
finished=0
work=""
cleanup() {
  [ -z "$work" ] || rm -rf "$work"
  if [ "$finished" -ne 1 ]; then
    if [ "$created_output" -eq 1 ]; then
      rm -rf "$output"
    elif [ -d "$output" ]; then
      find "$output" -mindepth 1 -delete 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT

work="$(mktemp -d)"
if [ ! -d "$output" ]; then
  mkdir -p "$output"
  created_output=1
fi
output="$(cd "$output" && pwd)"
mkdir -p "$output/packages"

# --- platform versions -------------------------------------------------------------

expected_entries="$(printf '%s\n' "${ENTRIES[@]}")"
packed=()
for spec in "${PLATFORMS[@]}"; do
  platform="${spec%%=*}"
  target="${spec#*=}"
  tarball="$dist/$PKG-$version-$target.tar.gz"
  names="$(tar -tzf "$tarball")"
  [ "$names" = "$expected_entries" ] \
    || die "$(basename "$tarball") lists $(tr '\n' ' ' <<<"$names")instead of ${ENTRIES[*]}"
  extracted="$work/$target"
  mkdir -p "$extracted"
  tar -xzf "$tarball" -C "$extracted"
  [ -f "$extracted/airs" ] && [ ! -L "$extracted/airs" ] && [ -x "$extracted/airs" ] \
    || die "$(basename "$tarball"): airs is not an executable regular file"

  dir="$output/packages/$platform"
  mkdir -p "$dir/vendor/$target"
  cp "$extracted/airs" "$dir/vendor/$target/airs"
  chmod 0755 "$dir/vendor/$target/airs"
  cmp -s "$dir/vendor/$target/airs" "$extracted/airs" || die "$platform: the staged airs differs from the release binary"
  cp "$extracted/LICENSE" "$extracted/NOTICE" "$dir/"
  if [ "$platform" = darwin-arm64 ] && [ "$verify_signature" -eq 1 ]; then
    codesign --verify --strict "$dir/vendor/$target/airs" \
      || die "$platform: the release airs fails codesign --verify --strict"
    echo "    ok: $platform: airs passes codesign --verify --strict"
  fi
  NAME="$NAME" VERSION="$version" PLATFORM="$platform" TARGET="$target" DIR="$dir" node --input-type=module -e '
    import { readFileSync, writeFileSync } from "node:fs";
    const { NAME, VERSION, PLATFORM, TARGET, DIR } = process.env;
    const template = JSON.parse(readFileSync(process.argv[1], "utf8"));
    const [os, cpu] = PLATFORM.split("-");
    const manifest = {
      name: NAME,
      version: `${VERSION}-${PLATFORM}`,
      description: `The ${TARGET} binary of ${NAME} ${VERSION} (installed by ${NAME}; do not install it directly)`,
      license: template.license,
      homepage: template.homepage,
      repository: template.repository,
      os: [os],
      cpu: [cpu],
      files: [`vendor/${TARGET}/airs`, "README.md", "LICENSE", "NOTICE"],
    };
    writeFileSync(`${DIR}/package.json`, JSON.stringify(manifest, null, 2) + "\n");
    writeFileSync(
      `${DIR}/README.md`,
      `# ${NAME} ${VERSION}-${PLATFORM}\n\nThe prebuilt \`airs\` binary for ${TARGET}, installed by \`${NAME}\` ${VERSION} as an optional dependency. Install \`${NAME}\` instead of this version.\n`,
    );
  ' "$ROOT/npm/package.json"
  echo "    staged $platform ($target)"
done

# --- the launcher package -------------------------------------------------------------

main="$output/packages/main"
mkdir -p "$main/bin" "$main/lib"
cp "$ROOT/npm/bin/airs.js" "$main/bin/airs.js"
chmod 0755 "$main/bin/airs.js"
cp "$ROOT/npm/lib/launcher.js" "$main/lib/launcher.js"
cp "$ROOT/npm/README.md" "$ROOT/LICENSE" "$ROOT/NOTICE" "$main/"
platform_list="$(printf '%s\n' "${PLATFORMS[@]}" | cut -d= -f1 | tr '\n' ' ')"
NAME="$NAME" VERSION="$version" PLATFORMS="$platform_list" DIR="$main" node --input-type=module -e '
  import { readFileSync, writeFileSync } from "node:fs";
  const { NAME, VERSION, PLATFORMS, DIR } = process.env;
  const manifest = JSON.parse(readFileSync(process.argv[1], "utf8"));
  const platforms = PLATFORMS.trim().split(" ");
  const aliases = Object.keys(manifest.optionalDependencies ?? {});
  const wanted = platforms.map((p) => `${NAME}-${p}`);
  if (manifest.name !== NAME || JSON.stringify(aliases) !== JSON.stringify(wanted)) {
    console.error(`npm-package: npm/package.json must be ${NAME} with the optional dependencies ${wanted.join(", ")}`);
    process.exit(1);
  }
  manifest.version = VERSION;
  for (const platform of platforms) {
    manifest.optionalDependencies[`${NAME}-${platform}`] = `npm:${NAME}@${VERSION}-${platform}`;
  }
  writeFileSync(`${DIR}/package.json`, JSON.stringify(manifest, null, 2) + "\n");
' "$ROOT/npm/package.json"
echo "    staged the launcher package"

# --- pack and check ------------------------------------------------------------------

# A private npm configuration: no user .npmrc (and no token in it) is read.
npmrc="$work/npmrc"
: >"$npmrc"
pack() {
  local dir="$1" file
  file="$(cd "$dir" && npm_config_userconfig="$npmrc" npm_config_update_notifier=false \
    npm pack --ignore-scripts --silent --pack-destination "$output")"
  file="$(tail -n 1 <<<"$file")"
  [ -f "$output/$file" ] || die "npm pack wrote no $file for $dir"
  echo "$file"
}
check_contents() {
  local file="$1" expected="$2" got
  got="$(tar -tzf "$output/$file" | sort)"
  [ "$got" = "$(sort <<<"$expected")" ] || die "$file holds $(tr '\n' ' ' <<<"$got")instead of $(tr '\n' ' ' <<<"$expected")"
}
for spec in "${PLATFORMS[@]}"; do
  platform="${spec%%=*}"
  target="${spec#*=}"
  file="$(pack "$output/packages/$platform")"
  [ "$file" = "cdot65-prisma-airs-cli-$version-$platform.tgz" ] || die "unexpected npm pack name $file"
  packed+=("$file")
  check_contents "$file" "$(printf 'package/%s\n' package.json README.md LICENSE NOTICE "vendor/$target/airs")"
done
file="$(pack "$main")"
[ "$file" = "cdot65-prisma-airs-cli-$version.tgz" ] || die "unexpected npm pack name $file"
packed+=("$file")
check_contents "$file" "$(printf 'package/%s\n' package.json README.md LICENSE NOTICE bin/airs.js lib/launcher.js)"

(cd "$output" && sha256 "${packed[@]}" >SHA256SUMS)
finished=1
echo "npm-package: staged $NAME $version in $output"
for file in "${packed[@]}"; do
  echo "    $file"
done
echo "next: publish the platform versions, then the launcher (docs/RELEASING.md §7)"
