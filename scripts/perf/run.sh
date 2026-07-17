#!/bin/sh
set -eu

if [ "${TARGET:-}" = "" ] || [ "${MANAGEMENT_URL:-}" = "" ]; then
  echo "TARGET and MANAGEMENT_URL are required" >&2
  exit 2
fi

PROTOCOL=${PROTOCOL:-tls}
HOST=${HOST:-example.com}
REQUESTS=${REQUESTS:-1000}
CONCURRENCY=${CONCURRENCY:-100}
PROFILE_SECONDS=${PROFILE_SECONDS:-30}
OUTPUT_ROOT=${OUTPUT_ROOT:-performance-results}
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
RUN_DIR="$OUTPUT_ROOT/$RUN_ID-$PROTOCOL-c$CONCURRENCY"
mkdir -p "$RUN_DIR"

CONFIG_SHA256=not-provided
if [ "${CONFIG_FILE:-}" != "" ]; then
  CONFIG_SHA256=$(shasum -a 256 "$CONFIG_FILE" | awk '{print $1}')
fi
if test -z "$(git status --porcelain)"; then
  DIRTY=false
else
  DIRTY=true
fi

{
  echo "schema=sakhtar-wg-performance-manifest/v1"
  echo "commit=$(git rev-parse HEAD)"
  echo "dirty=$DIRTY"
  echo "toolchain=$(go env GOVERSION)"
  echo "goos=$(go env GOOS)"
  echo "goarch=$(go env GOARCH)"
  echo "config_sha256=$CONFIG_SHA256"
  echo "target=$TARGET"
  echo "management_url=$MANAGEMENT_URL"
  echo "protocol=$PROTOCOL"
  echo "host=$HOST"
  echo "requests=$REQUESTS"
  echo "concurrency=$CONCURRENCY"
  uname -a
} > "$RUN_DIR/manifest.txt"

go test -run='^$' -bench=. -benchmem -count=8 \
  ./internal/proxy ./internal/dns ./internal/routing ./internal/routesource ./cmd/sakhtar-wg \
  > "$RUN_DIR/bench.txt"
go build -trimpath -o "$RUN_DIR/loadgen" ./cmd/loadgen

curl -fsS "$MANAGEMENT_URL/debug/pprof/profile?seconds=$PROFILE_SECONDS" -o "$RUN_DIR/cpu.pprof" &
CPU_PID=$!
curl -fsS "$MANAGEMENT_URL/debug/pprof/trace?seconds=$PROFILE_SECONDS" -o "$RUN_DIR/trace.out" &
TRACE_PID=$!

"$RUN_DIR/loadgen" \
  -target "$TARGET" \
  -management-url "$MANAGEMENT_URL" \
  -protocol "$PROTOCOL" \
  -host "$HOST" \
  -requests "$REQUESTS" \
  -concurrency "$CONCURRENCY" \
  -output "$RUN_DIR/load.json" \
  "$@"

wait "$CPU_PID"
wait "$TRACE_PID"
for PROFILE in heap allocs mutex block goroutine; do
  curl -fsS "$MANAGEMENT_URL/debug/pprof/$PROFILE" -o "$RUN_DIR/$PROFILE.pprof"
  go tool pprof -top "$RUN_DIR/$PROFILE.pprof" > "$RUN_DIR/$PROFILE-top.txt"
done
go tool pprof -top "$RUN_DIR/cpu.pprof" > "$RUN_DIR/cpu-top.txt"

echo "$RUN_DIR"
