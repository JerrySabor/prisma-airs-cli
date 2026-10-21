#!/usr/bin/env bash
# Renders the Homebrew formula Formula/airs-cli.rb for a published airs-cli version.
# docs/RELEASING.md §6 is the guide; DESIGN §21.8 and §21.9 are the contract. usage()
# below holds the usage text (--help prints it, and every exit-2 refusal prints it on
# stderr).
#
# Without --checksum or --metadata-file the checksum comes from crates.io's public API,
# and the .crate file is downloaded and hashed to confirm it. No credential is sent or
# read. The default output is target/homebrew/Formula/airs-cli.rb; an existing file is
# replaced whole or not at all. The script never commits, pushes or publishes anything.
set -Eeuo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="airs-cli"
TEMPLATE="$ROOT/packaging/homebrew/airs-cli.rb.in"
DEFAULT_OUTPUT="$ROOT/target/homebrew/Formula/airs-cli.rb"
USER_AGENT="airs-cli-homebrew-formula (+https://git.cdot.io/cdot/prisma-airs-cli-rs)"
# 64 MiB: far above the crate's size, a bound on what a broken answer can make us store.
MAX_CRATE_BYTES=67108864

usage() {
  cat <<'USAGE'
  scripts/homebrew-formula.sh <version> [--checksum <sha256> | --metadata-file <path>]
                              [--output <path> | --output -]

  <version>               a stable release published on crates.io (e.g. 1.0.0, no v)
  --checksum <sha256>     the .crate file's SHA-256 (64 lowercase hex); no network
  --metadata-file <path>  a saved answer of https://crates.io/api/v1/crates/airs-cli/<v>;
                          no network
  --output <path>         write the formula here (the directory must exist)
  --output -              write the formula to standard output
USAGE
}

usage_error() {
  echo "homebrew-formula: $*" >&2
  usage >&2
  exit 2
}

die() {
  echo "homebrew-formula: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH${2:+ ($2)}"
}

# --- arguments --------------------------------------------------------------------

version=""
checksum=""
checksum_given=0
metadata_file=""
metadata_given=0
output=""
output_given=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --checksum | --metadata-file | --output)
      # A value is never another option: `--checksum --output x` lacks the checksum.
      # Only --output takes the value `-` (standard output).
      if [ "$#" -lt 2 ] || { [[ "$2" == -* ]] && ! { [ "$1" = --output ] && [ "$2" = - ]; }; }; then
        usage_error "$1 needs a value"
      fi
      case "$1" in
        --checksum)
          [ "$checksum_given" -eq 0 ] || usage_error "--checksum given more than once"
          checksum_given=1
          checksum="$2"
          ;;
        --metadata-file)
          [ "$metadata_given" -eq 0 ] || usage_error "--metadata-file given more than once"
          metadata_given=1
          metadata_file="$2"
          ;;
        --output)
          [ "$output_given" -eq 0 ] || usage_error "--output given more than once"
          output_given=1
          output="$2"
          ;;
      esac
      shift 2
      ;;
    -?*)
      usage_error "unknown option: $1"
      ;;
    *)
      [ -z "$version" ] || usage_error "more than one version given"
      version="$1"
      shift
      ;;
  esac
done

[ -n "$version" ] || usage_error "no version given"
if [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+- ]]; then
  usage_error "$version is a pre-release; the tap carries stable releases only"
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || usage_error "'$version' is not a version like 1.0.0 (no leading v)"
if [ "$checksum_given" -eq 1 ] && [ "$metadata_given" -eq 1 ]; then
  usage_error "--checksum and --metadata-file exclude each other"
fi
if [ "$checksum_given" -eq 1 ] && ! [[ "$checksum" =~ ^[0-9a-f]{64}$ ]]; then
  usage_error "--checksum needs a SHA-256 of 64 lowercase hex digits"
fi
[ "$metadata_given" -eq 0 ] || [ -n "$metadata_file" ] || usage_error "--metadata-file needs a path"
[ "$output_given" -eq 0 ] || [ -n "$output" ] || usage_error "--output needs a path or -"

# --- temporary files, removed on every exit ---------------------------------------

work=""
partial=""
cleanup() {
  [ -z "$partial" ] || rm -f "$partial"
  [ -z "$work" ] || rm -rf "$work"
}
trap cleanup EXIT

private_dir() {
  if [ -z "$work" ]; then
    work="$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/airs-homebrew-formula.XXXXXX")"
  fi
}

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    die "shasum or sha256sum is required but neither is on PATH"
  fi
}

# --- the checksum -----------------------------------------------------------------

# check_answer <file>: prints the checksum of a crates.io version answer, or dies naming
# the first check that failed. The file must hold exactly one JSON document (-s reads
# them all into one array): two documents would make jq print two verdicts.
check_answer() {
  local verdict
  need jq "it reads the crates.io answer"
  # \A and \z: jq's $ also matches before a final newline, so test("^…$") would pass
  # "<hex>\n", and the command substitution below would then strip that newline.
  verdict="$(jq -r -s --arg crate "$CRATE" --arg num "$version" '
    if length != 1 then "the answer is not JSON"
    else .[0] |
      if type != "object" or (.version | type) != "object" then "no version object"
      elif .version.crate != $crate then "the crate is not \($crate)"
      elif .version.num != $num then "the version is not \($num)"
      elif .version.yanked == true then "the version is yanked"
      elif .version.yanked != false then "no yanked flag"
      elif (.version.checksum | type) != "string" then "no checksum"
      elif (.version.checksum | test("\\A[0-9a-f]{64}\\z")) | not then "the checksum is not 64 lowercase hex"
      else "ok \(.version.checksum)"
      end
    end' "$1" 2>/dev/null)" || verdict="the answer is not JSON"
  case "$verdict" in
    "ok "*) printf '%s\n' "${verdict#ok }" ;;
    *) die "crates.io has no usable $CRATE $version ($verdict)" ;;
  esac
}

if [ "$checksum_given" -eq 1 ]; then
  echo "homebrew-formula: checksum from --checksum" >&2
elif [ "$metadata_given" -eq 1 ]; then
  [ -f "$metadata_file" ] && [ -r "$metadata_file" ] || die "cannot read $metadata_file"
  checksum="$(check_answer "$metadata_file")"
  echo "homebrew-formula: checksum from $metadata_file" >&2
else
  need curl
  need jq "it reads the crates.io answer"
  private_dir
  api="https://crates.io/api/v1/crates/$CRATE/$version"
  # -q (--disable) must be curl's first argument: curl then reads no .curlrc, so the
  # maintainer's curl config (a user, header, netrc or insecure line) never reaches crates.io.
  curl_flags=(-q -sS --fail --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 30 -A "$USER_AGENT")
  echo "homebrew-formula: fetching $api" >&2
  rc=0
  curl "${curl_flags[@]}" -o "$work/answer.json" "$api" || rc=$?
  [ "$rc" -eq 0 ] || die "cannot fetch $api (curl exit $rc)"
  checksum="$(check_answer "$work/answer.json")"
  download="$api/download"
  echo "homebrew-formula: downloading $download to confirm the checksum" >&2
  rc=0
  curl "${curl_flags[@]}" --location --max-filesize "$MAX_CRATE_BYTES" -o "$work/crate" "$download" || rc=$?
  [ "$rc" -eq 0 ] || die "cannot fetch $download (curl exit $rc)"
  got="$(sha256_of "$work/crate")"
  [ "$got" = "$checksum" ] \
    || die "the downloaded $CRATE-$version.crate has sha256 $got, crates.io says $checksum"
  echo "homebrew-formula: checksum from crates.io, confirmed by the downloaded .crate" >&2
fi

# --- render -----------------------------------------------------------------------

# Whatever the source, the checksum reaches the template only as one 64-hex-digit line.
[[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || die "the checksum '$checksum' is not 64 lowercase hex"
[ -f "$TEMPLATE" ] || die "the template $TEMPLATE is missing"
# The version matches ^[0-9]+\.[0-9]+\.[0-9]+$ and the checksum ^[0-9a-f]{64}$ (both
# checked above), so neither holds a sed metacharacter, a / or a newline.
render() {
  sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$checksum/g" "$TEMPLATE"
}
rendered="$(render)"
if grep -q '@[A-Z0-9_]*@' <<<"$rendered"; then
  die "the template $TEMPLATE has a placeholder this script does not fill"
fi
grep -q "^class AirsCli < Formula\$" <<<"$rendered" || die "the template $TEMPLATE has no class AirsCli"

if [ "$output" = - ]; then
  printf '%s\n' "$rendered"
  echo "homebrew-formula: wrote standard output ($CRATE $version, sha256 $checksum)" >&2
  exit 0
fi

if [ -z "$output" ]; then
  output="$DEFAULT_OUTPUT"
  mkdir -p "$(dirname "$output")"
fi
dir="$(dirname "$output")"
[ -d "$dir" ] || die "the directory of $output does not exist"
[ ! -d "$output" ] || die "$output is a directory"
partial="$(mktemp "$dir/.airs-cli.rb.XXXXXX")"
printf '%s\n' "$rendered" > "$partial"
chmod 0644 "$partial"
mv -f "$partial" "$output"
partial=""
echo "homebrew-formula: wrote $output ($CRATE $version, sha256 $checksum)" >&2
