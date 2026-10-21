#!/usr/bin/env bash
# Packages release binaries into tarballs and SHA256SUMS. scripts/release.sh calls it;
# docs/RELEASING.md §3 and DESIGN §21.7 describe the layout. usage() below holds the
# usage text (--help prints it, and every exit-2 refusal prints it on stderr).
#
# Each tarball, <dist>/airs-cli-<version>-<target>.tar.gz, holds exactly airs (0755),
# airs-cli-rs (a relative symlink to airs, the 1.x compatibility name), README.md and
# LICENSE (0644), owned by root:root, with no AppleDouble files or extended attributes.
# SHA256SUMS lists the tarballs. Every tarball is listed and extracted again to check
# its layout. A refusal writes nothing; a failure removes what this run wrote.
set -Eeuo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="airs"
COMPAT_BIN="airs-cli-rs"
PKG="airs-cli"
ENTRIES=("$BIN" "$COMPAT_BIN" README.md LICENSE)

usage() {
  cat <<'USAGE'
  scripts/package-release.sh [--run-check <target>] [--verify-signature <target>]
                             <version> <dist> <target>=<binary>...

  <version>                    the release version (e.g. 1.0.0, no leading v)
  <dist>                       the output directory; it must be absent or empty
  <target>=<binary>            a rust target and the airs binary built for it
  --run-check <target>         run the packaged airs and airs-cli-rs --version for
                               this target (it must run on this machine)
  --verify-signature <target>  run codesign --verify --strict on this target's
                               packaged airs (macOS)
USAGE
}

usage_error() {
  echo "package-release: $*" >&2
  usage >&2
  exit 2
}

die() {
  echo "package-release: $*" >&2
  exit 1
}

# --- arguments --------------------------------------------------------------------

run_check=""
verify_signature=""
positional=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --run-check | --verify-signature)
      # A target is never another option: `--run-check --verify-signature x` lacks the
      # run-check target (as homebrew-formula.sh refuses an option-like value).
      if [ "$#" -lt 2 ] || [ -z "$2" ] || [[ "$2" == -* ]]; then
        usage_error "$1 needs a target"
      fi
      if [ "$1" = --run-check ]; then
        [ -z "$run_check" ] || usage_error "--run-check given more than once"
        run_check="$2"
      else
        [ -z "$verify_signature" ] || usage_error "--verify-signature given more than once"
        verify_signature="$2"
      fi
      shift 2
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
# An empty argument is refused before anything else: an empty <dist> would point the
# cleanup at /.stage and /.verify.
i=0
for arg in ${positional[@]+"${positional[@]}"}; do
  if [ -z "$arg" ]; then
    case "$i" in
      0) usage_error "the <version> argument is empty" ;;
      1) usage_error "the <dist> argument is empty" ;;
      *) usage_error "a <target>=<binary> argument is empty" ;;
    esac
  fi
  i=$((i + 1))
done
[ "${#positional[@]}" -ge 3 ] || usage_error "needs a version, a dist directory and at least one <target>=<binary>"
version="${positional[0]}"
dist="${positional[1]}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
  || usage_error "'$version' is not a version like 1.0.0 (no leading v)"

targets=()
binaries=()
for spec in "${positional[@]:2}"; do
  target="${spec%%=*}"
  binary="${spec#*=}"
  [ "$target" != "$spec" ] && [ -n "$binary" ] || usage_error "'$spec' is not <target>=<binary>"
  [[ "$target" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]] || usage_error "'$target' is not a target name"
  for seen in ${targets[@]+"${targets[@]}"}; do
    [ "$seen" != "$target" ] || usage_error "target $target given more than once"
  done
  targets+=("$target")
  binaries+=("$binary")
done
for flag_target in "$run_check" "$verify_signature"; do
  [ -n "$flag_target" ] || continue
  found=0
  for target in "${targets[@]}"; do
    [ "$target" != "$flag_target" ] || found=1
  done
  [ "$found" -eq 1 ] || usage_error "$flag_target is not one of the packaged targets"
done

# --- preconditions: nothing is written before every one holds ---------------------

tar --version 2>/dev/null | head -1 | grep -q '^bsdtar ' \
  || die "tar is not bsdtar (it must store the link as a link and drop macOS metadata)"
command -v shasum >/dev/null 2>&1 || die "shasum is required but not on PATH"
if [ -n "$verify_signature" ]; then
  command -v codesign >/dev/null 2>&1 || die "codesign is required for --verify-signature"
fi
if [ -e "$dist" ] || [ -L "$dist" ]; then
  [ -d "$dist" ] && [ ! -L "$dist" ] || die "$dist exists and is not a directory"
  [ -z "$(ls -A "$dist")" ] || die "$dist exists and is not empty"
fi
for file in README.md LICENSE; do
  [ -f "$ROOT/$file" ] || die "$ROOT/$file is missing"
done
i=0
while [ "$i" -lt "${#targets[@]}" ]; do
  binary="${binaries[$i]}"
  [ -f "$binary" ] || die "${targets[$i]}: $binary is missing or not a file"
  [ -x "$binary" ] || die "${targets[$i]}: $binary is not executable"
  i=$((i + 1))
done

# --- cleanup: a failure leaves nothing this run wrote -----------------------------

created_dist=0
written=()
finished=0
cleanup() {
  rm -rf "$dist/.stage" "$dist/.verify"
  if [ "$finished" -ne 1 ]; then
    for file in ${written[@]+"${written[@]}"}; do
      rm -f "$dist/$file"
    done
    if [ "$created_dist" -eq 1 ]; then
      rmdir "$dist" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT

if [ ! -d "$dist" ]; then
  mkdir -p "$dist"
  created_dist=1
fi

mode_of() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

# --- package ----------------------------------------------------------------------

tarballs=()
i=0
while [ "$i" -lt "${#targets[@]}" ]; do
  target="${targets[$i]}"
  binary="${binaries[$i]}"
  name="$PKG-$version-$target"
  stage="$dist/.stage/$name"
  mkdir -p "$stage"
  cp "$binary" "$stage/$BIN"
  chmod 0755 "$stage/$BIN"
  (cd "$stage" && ln -s "$BIN" "$COMPAT_BIN")
  cp "$ROOT/README.md" "$ROOT/LICENSE" "$stage/"
  chmod 0644 "$stage/README.md" "$stage/LICENSE"
  # No AppleDouble files or extended attributes; root-owned entries; the link is
  # stored as a link (bsdtar does not follow it without -L).
  written+=("$name.tar.gz")
  COPYFILE_DISABLE=1 tar --no-mac-metadata --uid 0 --gid 0 --uname root --gname root \
    -czf "$dist/$name.tar.gz" -C "$stage" "${ENTRIES[@]}"
  tarballs+=("$name.tar.gz")
  echo "    packaged $name.tar.gz"
  i=$((i + 1))
done
rm -rf "$dist/.stage"
written+=(SHA256SUMS)
(cd "$dist" && shasum -a 256 "${tarballs[@]}" > SHA256SUMS)

# --- check what was packaged -------------------------------------------------------

expected_names="$(printf '%s\n' "${ENTRIES[@]}")"
i=0
while [ "$i" -lt "${#targets[@]}" ]; do
  target="${targets[$i]}"
  tarball="$dist/${tarballs[$i]}"
  names="$(tar -tzf "$tarball")"
  [ "$names" = "$expected_names" ] \
    || die "${tarballs[$i]} lists $(tr '\n' ' ' <<<"$names")instead of ${ENTRIES[*]}"
  # bsdtar -tv: <mode> <links> <owner> <group> <size> <date...> <name> [-> <target>]
  listing="$(tar -tvzf "$tarball")"
  owners="$(awk '{ print $3 ":" $4 }' <<<"$listing" | sort -u)"
  [ "$owners" = "root:root" ] || die "${tarballs[$i]} has entries not owned by root:root"
  modes="$(awk '{ print $1 }' <<<"$listing" | tr '\n' ' ')"
  [[ "$modes" =~ ^-rwxr-xr-x\ l[rwx-]{9}\ -rw-r--r--\ -rw-r--r--\ $ ]] \
    || die "${tarballs[$i]} has the modes $modes"
  link_line="$(sed -n 2p <<<"$listing")"
  [[ "$link_line" == *" $COMPAT_BIN -> $BIN" ]] || die "${tarballs[$i]}: $COMPAT_BIN is not a link to $BIN"

  verify="$dist/.verify/$target"
  mkdir -p "$verify"
  tar -xzf "$tarball" -C "$verify"
  [ -f "$verify/$BIN" ] && [ ! -L "$verify/$BIN" ] || die "${tarballs[$i]}: $BIN is not a regular file"
  [ "$(mode_of "$verify/$BIN")" = 755 ] || die "${tarballs[$i]}: $BIN is not 0755"
  [ -L "$verify/$COMPAT_BIN" ] || die "${tarballs[$i]}: $COMPAT_BIN is not a symlink"
  [ "$(readlink "$verify/$COMPAT_BIN")" = "$BIN" ] || die "${tarballs[$i]}: $COMPAT_BIN does not point to $BIN"
  for file in README.md LICENSE; do
    [ -f "$verify/$file" ] && [ ! -L "$verify/$file" ] || die "${tarballs[$i]}: $file is not a regular file"
    [ "$(mode_of "$verify/$file")" = 644 ] || die "${tarballs[$i]}: $file is not 0644"
    cmp -s "$verify/$file" "$ROOT/$file" || die "${tarballs[$i]}: $file differs from the repository's"
  done
  cmp -s "$verify/$BIN" "${binaries[$i]}" || die "${tarballs[$i]}: $BIN differs from ${binaries[$i]}"
  if [ "$target" = "$run_check" ]; then
    for name in "$BIN" "$COMPAT_BIN"; do
      got="$(cd "$verify" && "./$name" --version)" || die "${tarballs[$i]}: ./$name --version failed"
      [ "$got" = "$version" ] || die "${tarballs[$i]}: ./$name --version prints '$got', expected '$version'"
    done
    echo "    ok: ${tarballs[$i]}: ./$BIN --version and ./$COMPAT_BIN --version print $version"
  fi
  if [ "$target" = "$verify_signature" ]; then
    codesign --verify --strict "$verify/$BIN" \
      || die "${tarballs[$i]}: the packaged $BIN fails codesign --verify --strict"
    echo "    ok: ${tarballs[$i]}: the packaged $BIN passes codesign --verify --strict"
  fi
  echo "    ok: ${tarballs[$i]}: ${ENTRIES[*]}; $COMPAT_BIN -> $BIN; modes 0755/0644; root:root"
  i=$((i + 1))
done
rm -rf "$dist/.verify"

sums="$(cut -d' ' -f3- "$dist/SHA256SUMS")"
[ "$sums" = "$(printf '%s\n' "${tarballs[@]}")" ] || die "SHA256SUMS does not list exactly the tarballs"
(cd "$dist" && shasum -a 256 -c --quiet SHA256SUMS) || die "SHA256SUMS does not match the tarballs"
finished=1
