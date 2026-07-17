#!/bin/sh
set -eu

DIST=${1:-dist}
VERSION=${VERSION:-$(awk -F= '$1 == "version" {print $2}' "$DIST/BUILD-METADATA.txt")}
COMMIT=${COMMIT:-$(awk -F= '$1 == "commit" {print $2}' "$DIST/BUILD-METADATA.txt")}
TOOLCHAIN=${TOOLCHAIN:-$(awk -F= '$1 == "toolchain" {print $2}' "$DIST/BUILD-METADATA.txt")}

(
  cd "$DIST"
  shasum -a 256 -c SHA256SUMS
)

for ARCH in amd64 arm64; do
  BINARY="$DIST/sakhtar-wg-linux-$ARCH"
  test -x "$BINARY"
  file "$BINARY" | grep -q 'statically linked'
  go version -m "$BINARY" | grep -F 'CGO_ENABLED=0' >/dev/null
  strings "$BINARY" | grep -F "$VERSION" >/dev/null
  strings "$BINARY" | grep -F "$COMMIT" >/dev/null
  strings "$BINARY" | grep -F "$TOOLCHAIN" >/dev/null
done

if [ "$(go env GOOS)" = linux ] && [ "$(go env GOARCH)" = amd64 ]; then
  VERSION_JSON=$($DIST/sakhtar-wg-linux-amd64 version -json)
  printf '%s' "$VERSION_JSON" | grep -F '"version": "'"$VERSION"'"' >/dev/null
  printf '%s' "$VERSION_JSON" | grep -F '"commit": "'"$COMMIT"'"' >/dev/null
fi

if [ "${VERIFY_REPRODUCIBLE:-0}" = 1 ]; then
  REPRO_DIR=$(mktemp -d)
  trap 'rm -rf "$REPRO_DIR"' EXIT HUP INT TERM
  VERSION="$VERSION" COMMIT="$COMMIT" SOURCE_DATE_EPOCH="$(awk -F= '$1 == "source_date_epoch" {print $2}' "$DIST/BUILD-METADATA.txt")" \
    scripts/build-release.sh "$REPRO_DIR"
  cmp "$DIST/sakhtar-wg-linux-amd64" "$REPRO_DIR/sakhtar-wg-linux-amd64"
  cmp "$DIST/sakhtar-wg-linux-arm64" "$REPRO_DIR/sakhtar-wg-linux-arm64"
fi
