# Architecture

sakhtar-wg is a single privileged Go daemon with a narrow management API and
several independently bounded control loops. Kernel WireGuard performs crypto;
the daemon owns interface configuration, policy routing, optional gateway
firewall rules, hostname-based proxying, route-source refresh, health failover,
and optional pfSense synchronization.

## Data and control paths

```text
client TCP
  -> source ACL and admission caps
  -> bounded TLS ClientHello / HTTP Host peek
  -> canonical hostname and most-specific suffix route
  -> bounded, generation-aware DNS cache
  -> egress-scoped destination policy
  -> bounded address selection and SO_MARK dial
  -> io.Copy in both directions

config / route sources / health
  -> validation and pure desired-state plans
  -> ownership and collision checks
  -> single-threaded kernel/firewall reconciliation
  -> generation publication and redacted observability
```

`cmd/sakhtar-wg/main.go` owns startup, reload, rollback, and shutdown ordering.
`cmd/sakhtar-wg/sni.go` owns
listener admission, protocol parsing, resolution/dial, established sessions,
and graceful drain. `internal/dns` owns fixed-capacity positive/negative caches
and cache-owned singleflight resolution. `internal/proxy` owns address
selection and attempt caps. `internal/routing` and `internal/routesource` hold
pure hot-path/set algorithms. `internal/kernel` and `internal/firewall` compile
deterministic ownership-safe plans. Linux effectors live behind build tags.

The management server in `internal/observability` is loopback/Unix-only and
serves liveness, drift/generation-aware readiness, bounded-label Prometheus
metrics, and redacted status. pprof is explicit opt-in on that same local trust
boundary; enabling it also enables mutex/block sampling for the duration of the
server.

## Trust and lifecycle

Candidate config is fully parsed and validated before apply. Kernel and
firewall mutation is serialized. A reload builds a new immutable router/DNS
generation and atomically publishes it; existing sessions retain their
generation. Host-state ownership is proven with reserved aliases, protocols,
marks/masks, priorities, tables, and firewall comments. Colliding foreign state
is blocking drift, never an adoption hint.

Route sources have bounded response bodies and total timeouts. Successful data
is normalized, deduplicated, persisted atomically, and retained on fetch
failure. pfSense sync uses a pinned known-hosts file, batch SSH, a forced-command
design, aggregate-change detection, and a minimum-network guard.

## Resource model

Active sessions are bounded by `max_connections` and optionally by source.
Protocol buffers, DNS positive/negative entries, pending resolutions, connect
attempts, resolver time, dial time, source bodies, management headers, active
probes, and shutdown grace are all config-bounded. Unique-host attacks can
cause eviction and rejection but cannot make cache size grow without bound.
The standard library's `io.Copy` datapath is retained unless cross-kernel
profiles demonstrate a safer material improvement.

## Distribution

Production releases are static Linux amd64/arm64 binaries. systemd provides the
state/runtime directories, capability ceiling, read-only system filesystem,
private temp, process visibility restrictions, and `NoNewPrivileges`. The
container includes iproute2, iptables, SSH, and CA roots because optional
runtime paths execute those tools; deployments should use a read-only rootfs
with only `/run/sakhtar-wg` and `/var/lib/sakhtar-wg` writable.
