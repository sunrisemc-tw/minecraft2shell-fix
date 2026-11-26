#!/usr/bin/env bash
# Downloads the published minecraft2shell proof-of-concept resource pack and runs
# the scanner over every font it ships. This is the "does it catch the real
# thing" check; it never executes font code, it only reads bytes.
#
#   tools/verify-poc-pack.sh
#
# Expects a built core jar:  mvn -q -pl core -am package
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
core_jar="$root/core/target/m2sfix-core-2.3.0.jar"
pack_url="https://raw.githubusercontent.com/bikini/minecraft2shell/main/resource-pack.zip"
work="${TMPDIR:-/tmp}/m2sfix-poc-pack"

if [[ ! -f "$core_jar" ]]; then
  echo "build first: mvn -q -pl core -am package" >&2
  exit 1
fi

rm -rf "$work"
mkdir -p "$work"
echo "downloading $pack_url"
curl -sfL -o "$work/resource-pack.zip" "$pack_url"
echo "sha1: $(sha1sum "$work/resource-pack.zip" | cut -d' ' -f1)"
unzip -q "$work/resource-pack.zip" -d "$work/pack"

# ScanFonts exits 1 when it flags something - which is exactly what we expect here, so the
# assertion is on the summary line, not on the exit code.
set +e
output="$(java -cp "$core_jar" dev.duckducktw.m2sfix.core.cli.ScanFonts "$work/pack")"
status=$?
set -e
echo "$output"

summary="$(printf '%s\n' "$output" | grep -E '^scanned=' | tail -1)"
echo "summary: $summary"

if [[ "$summary" != *"scanned=144"* || "$summary" != *"flagged=144"* ]]; then
  echo "FAIL: expected all 144 delivered fonts to be flagged (got: ${summary:-none})" >&2
  exit 1
fi
if [[ $status -ne 1 ]]; then
  echo "FAIL: ScanFonts should exit 1 when it flags fonts, got $status" >&2
  exit 1
fi
echo "OK: 144/144 delivered fonts flagged"
