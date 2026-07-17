# Health and observability operations

The management listener defaults to `127.0.0.1:9090`. It may instead use an
absolute Unix socket such as `unix:/run/sakhtar-wg/management.sock`. TCP
wildcard and non-loopback addresses are rejected during strict config loading.
The listener has explicit header-read, write, idle, header-size, and graceful
shutdown limits. pprof is disabled by default and can only be enabled on this
local listener.

## Endpoint semantics

| Endpoint | Success | Failure | Meaning |
|---|---:|---:|---|
| `/livez` | 200 | process unavailable | The process and management event loop can answer. It performs no DNS, WireGuard, kernel, firewall, route-source, pfSense, or probe check. |
| `/readyz` | 200 | 503 | A config generation is active, every required proxy listener is present, the last kernel/firewall reconcile succeeded, and measured owned-state drift is zero. |
| `/metrics` | 200 | — | Prometheus text format with the bounded label contract below. Collection reads existing aggregates and snapshots; it does no per-host or per-peer work. |
| `/status` | 200 | — | Detailed redacted generation, component, route-source, group-policy, WireGuard, and optional active-probe state. |

Readiness intentionally does not require a recent WireGuard handshake. A peer
can be idle and healthy, and a fresh handshake does not prove that an arbitrary
Internet destination works. Required kernel state and listeners gate readiness;
passive and active tunnel evidence informs status, failover, and targeted
alerts.

## Tunnel signals

- `wg_session_recent=recent`: the peer has a handshake younger than the group's
  configured `healthy_after` threshold.
- `wg_session_recent=idle_unknown`: a peer exists but its handshake is absent or
  old. This is not declared failed without additional evidence.
- `wg_session_recent=failed`: the device query failed or the expected peer is
  absent.
- Group `state` and `reason` report the chosen mark. When no member has a recent
  handshake, current policy is `degraded` with
  `no_recent_handshake_fail_open_primary`; the primary is retained.

Each health interval queries every unique WireGuard device once and derives all
member/group state from that immutable snapshot. It never performs one kernel
query per group membership.

An optional `health_probe` checks one operator-selected endpoint through a
configured tunnel mark. The endpoint is independent of customer traffic.
Configuration requires a timeout shorter than an interval of at least five
seconds, jitter from 0–100%, and a concurrency limit from 1–8. Endpoint URLs
with credentials are rejected. A failed probe is evidence about that probe
path, not a claim about every customer destination.

## Metric cardinality contract

Labels are limited to fixed enums plus config-bounded tunnel, group, and route
source names. The registry normalizes unexpected enum values to `other` before
storage, so thousands of unique inputs collapse into the same series.

The following values are never labels: SNI/Host, canonical hostname, client or
source IP, destination IP, URL, route/CIDR, peer public key, resolver address,
raw header, or config body. Route count changes a gauge value, not series count.
Peer traffic and handshake metrics use the configured tunnel name and never the
peer key. A cardinality test feeds thousands of hostname/source-IP-like values
and asserts a constant series bound.

Core metric families cover:

- active, accepted, rejected, and completed proxy sessions; duration and bytes;
- DNS cache entries/evictions, request outcomes, pending/rejected work, resolver
  outcomes and duration;
- reload result/duration and active generation;
- component readiness and kernel/firewall drift;
- WireGuard passive state, handshake age, and traffic by configured tunnel;
- group policy state/reason;
- route-source last success and prefix count, plus pfSync outcomes;
- optional active probe result/duration; and
- goroutines, heap, process uptime, and Linux open FDs.

## Redaction and logging contract

Logs are JSON and use stable event names such as `config.reload_completed`,
`lifecycle.shutdown_started`, and `health.group_selection_changed`. Lifecycle
and reload events include the active configuration generation, component, and
outcome.

The logging handler and component-status registry redact private and preshared
keys, passwords/tokens, authorization/cookie material, SSH/PEM material,
credential-bearing URLs, SNI/Host, raw headers, and config bodies. Config bodies
are never logged. `/status` stores only already-redacted error text. Do not add a
new log field or status field containing request identity without extending the
redaction and cardinality tests first.

## Reload and status flow

`sakhtar-wg reload` signals the running process. Every attempt increments a
bounded result counter and records duration. A successful commit advances the
active generation only after kernel, firewall, health topology, and proxy
routing converge. A failure retains the prior generation and logs the error
against that generation. Management bind/time-limit changes require a process
restart. Proxy listener and gateway list-listener address changes also require a
restart and are rejected as reload candidates; operational policy, health
topology, and proxy routing update in place.

## Suggested alerts

Alert on sustained symptoms, not isolated events:

- increase of `sakhtar_wg_reload_attempts_total{outcome="failure"}` or an active
  generation that did not advance after a deployment;
- `sakhtar_wg_component_ready == 0` for a required component over a sustained
  window;
- DNS pending rejection or eviction surges;
- proxy overload rejection rate;
- route-source last-success age beyond two configured refresh intervals;
- persistent non-zero kernel or firewall drift;
- every member of a required group lacking recent or successful active evidence
  under a fail-closed deployment policy; and
- goroutine, FD, or heap growth out of proportion to active sessions.

Do not alert on one old handshake without traffic and probe context.

## Troubleshooting flow

1. Check `/livez`. If it cannot answer, inspect process/service state rather
   than external dependencies.
2. Check `/readyz` and its reason list. A listener failure differs from kernel
   or firewall drift and should be handled separately.
3. Inspect `/status` for active generation, last component error, drift,
   route-source age, group reason, passive session state, and active-probe result.
4. Compare `/metrics` rates around the incident: reload failures, overload,
   DNS rejection, route-source age, pfSync outcomes, and resource growth.
5. For drift, run `sakhtar-wg plan -c /etc/sakhtar-wg/config.yaml`; do not mutate
   foreign host state. Follow `docs/OWNERSHIP.md`.
6. For tunnel symptoms, distinguish `idle_unknown` from `failed`, compare RX/TX
   movement, and use the independent active probe. Only then inspect the marked
   route/rule and upstream endpoint.
7. Correlate JSON logs by `generation`. Never paste deployed config or keys into
   incident notes.
