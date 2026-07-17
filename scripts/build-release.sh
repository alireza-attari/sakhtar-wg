#!/bin/sh
set -eu

OUTPUT_DIR=${1:-dist}
GO=${GO:-go}
VERSION=${VERSION:-$(git describe --tags --always --dirty)}
COMMIT=${COMMIT:-$(git rev-parse HEAD)}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}
TOOLCHAIN=$($GO env GOVERSION)

case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac

if date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ >/dev/null 2>&1; then
  BUILD_DATE=$(date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
else
  BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
fi

mkdir -p "$OUTPUT_DIR"
LDFLAGS="-s -w -buildid= -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE -X main.toolchain=$TOOLCHAIN"
for ARCH in amd64 arm64; do
  BINARY="$OUTPUT_DIR/sakhtar-wg-linux-$ARCH"
  GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 "$GO" build \
    -trimpath -buildvcs=true -ldflags "$LDFLAGS" -o "$BINARY" ./cmd/sakhtar-wg
  chmod 0755 "$BINARY"
done

(
  cd "$OUTPUT_DIR"
  shasum -a 256 sakhtar-wg-linux-amd64 sakhtar-wg-linux-arm64 > SHA256SUMS
)

{
  echo "version=$VERSION"
  echo "commit=$COMMIT"
  echo "build_date=$BUILD_DATE"
  echo "toolchain=$TOOLCHAIN"
  echo "source_date_epoch=$SOURCE_DATE_EPOCH"
} > "$OUTPUT_DIR/BUILD-METADATA.txt"
