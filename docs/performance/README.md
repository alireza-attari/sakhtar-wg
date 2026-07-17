# Performance engineering

Performance results should record the commit, a redacted configuration hash, Go
toolchain, kernel and architecture, workload, raw before/after output, and
relevant profiles. Do not publish the deployed configuration itself.

## Scenarios

Run both TLS ClientHello passthrough and HTTP Host passthrough through direct
and marked/tunnel egress. For each applicable path, cover:

| Dimension | Required values |
| --- | --- |
| Concurrency | 1, 100, 1,000, and configured `max_connections` |
| DNS state | cold miss, warm hit, expired+stale transient failure, NXDOMAIN/NODATA, and unique random subdomains above both capacities |
| Route state | small set and maximum configuration-accepted set; unchanged and changed reload |
| Backend | healthy, slow connect, unreachable, rotating mixed addresses, all unhealthy |
| Client | normal, malformed, oversized, slowloris handshake, idle stream, overload |
| Lifecycle | steady state, no-listener-change reload during traffic, shutdown drain, upgrade, rollback |

The success criteria are scenario-specific. A setup benchmark measures TCP
connect plus complete fixture write; set `-read-bytes` when the backend fixture
has a deterministic response and end-to-end success must include it. A
slowloris scenario is expected to be rejected by the configured handshake
deadline, not counted as a successful passthrough.

Use dedicated test infrastructure and deterministic local DNS/backend fixtures
where possible. Never direct load at third-party or production systems without
explicit authorization.

## Microbenchmarks

```sh
make benchmark
```

This records ClientHello parsing, HTTP Host parsing, suffix lookup at several
rule counts, DNS hit/miss, address selection, route merge/dedup, IPv4 CIDR
aggregation, and desired/current diff. Eight samples support `benchstat` noise
analysis. `make benchmark-smoke` compiles and executes every benchmark once in
CI but is not a performance comparison.

## Raw load and profiles

Enable `management.pprof: true` only on the loopback or mode-restricted Unix
management listener, restart the daemon, and run:

```sh
TARGET=127.0.0.1:443 \
MANAGEMENT_URL=http://127.0.0.1:9090 \
CONFIG_FILE=/etc/sakhtar-wg/config.yaml \
PROTOCOL=tls HOST=example.com REQUESTS=10000 CONCURRENCY=100 \
scripts/perf/run.sh
```

The runner stores:

- a manifest with commit, dirty state, toolchain, OS/architecture, config hash,
  target, protocol, request count, and concurrency;
- raw benchmark samples and a JSON load report with throughput, p50/p95/p99/max
  setup latency, failures, reload failures, DNS QPS, rejection deltas, and
  before/after heap/goroutine/FD/process metrics;
- CPU, heap, allocation, mutex, block, goroutine, and execution-trace files,
  plus text `pprof -top` summaries.

For a reload run, append `-reload-pid PID -reload-after 10s`. For a slowloris
run, use `-slowloris-bytes N`; each selected byte is sent one second apart.
Use HTTP target/host flags for the HTTP path. To capture completed responses,
set `-read-bytes` to a deterministic fixture response length.

Inspect artifacts with:

```sh
go tool pprof -top performance-results/RUN/cpu.pprof
go tool pprof -top performance-results/RUN/heap.pprof
go tool trace performance-results/RUN/trace.out
```

Server CPU is evaluated from the CPU profile, allocations from allocs/heap,
contention from mutex/block, scheduler/lifecycle behavior from trace/goroutine,
and FD/goroutine/cache bounds from management metrics. Client-side loadgen CPU
is not a substitute for server evidence.

## Gates and baseline approval

`docs/performance/gates.json` keeps correctness/resource invariants active while the
numeric benchmark gate is intentionally disabled. To enable it:

1. Select and document a supported Linux reference host/kernel and fixed
   config/backend/DNS fixtures.
2. Record at least eight samples per benchmark and three full load runs at the
   baseline commit under comparable idle-host conditions.
3. Use statistical comparison to establish per-benchmark noise bands; review
   p50/p95/p99 and resource profiles, not only means.
4. Commit the approved raw result reference, tool versions, regression bands,
   reviewer/date, and gate implementation. Never invent an absolute threshold
   from a different machine.

Invariant gates are zero goroutine/FD growth after overload plus a full churn
cycle, cache size bounded by configured capacity rather than unique hostname
count, zero successful-connection interruptions during a no-listener-change
reload, and green race/integration suites. Tests already exercise admission
growth, cache capacity/eviction, and active-session reload continuity; sustained
external runs remain required before a production claim.

## Optimization requirements

Preserve standard-library behavior and the documented security and lifecycle
invariants. Pooling, shard tuning, PGO, custom copy loops, and deadline changes
require a representative profile and cross-kernel before/after results. Include
race and integration results with CPU and allocation profiles.
