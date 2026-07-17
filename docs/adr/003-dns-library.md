# ADR 003: Keep `net.Resolver` and use local bounded TTL policy

Status: accepted  
Date: 2026-07-17

## Context

The DNS cache needs cancellation-safe resolution, authoritative negative versus
transient response classes, all A/AAAA addresses, marked resolver transport,
and bounded caching. Authoritative record TTL parsing is useful but is not
required to make those invariants correct. Adding a DNS client also expands the
network parser and retry surface, so the plan requires an explicit library
decision first.

## Decision

Use the standard library's [`net.Resolver`](https://pkg.go.dev/net#Resolver) for
runtime queries. Wrap it behind the typed `internal/dns.Resolver` interface and
assign results an explicitly named local positive TTL (`dns_cache_ttl`) clamped
by `dns_min_positive_ttl` and `dns_max_positive_ttl`.

Do not claim authoritative TTL compliance. Do not add a DNS dependency in Plan
003. Reconsider the decision only in a separate ADR with interoperability tests
for UDP truncation/TCP fallback, EDNS, CNAME chains, NXDOMAIN versus NODATA,
timeouts, cancellation, malformed messages, and marked sockets.

## Evidence and alternatives

- `net.Resolver` is maintained with Go, accepts contexts, returns all resolved
  addresses, is safe for concurrent use, and supports a custom `Dial` hook. The
  hook is required here to stamp resolver sockets with the selected tunnel mark.
  It does not expose record TTLs or a complete DNS response, which is why cache
  lifetimes are local policy.
- [`golang.org/x/net/dns/dnsmessage`](https://pkg.go.dev/golang.org/x/net/dns/dnsmessage)
  provides defensive message packing/parsing, but it is not a resolver. Adopting
  it would make this daemon responsible for query IDs, retries, EDNS sizing,
  truncation, TCP fallback, response validation, and CNAME processing. It remains
  useful for fuzzing a possible future wire layer, not for the current runtime.
- The official [`miekg/dns` v1 repository](https://github.com/miekg/dns) is
  BSD-3-Clause and implements UDP/TCP, EDNS0, and a full client, but its README
  states that v1 now receives only specific fixes and points new development to
  v2 on Codeberg. The v2 module/import stability, tagged-release maturity,
  cancellation contract, automatic truncation/TCP fallback behavior, and
  current security history could not all be verified from the available
  official package documentation. Under the plan's stop condition, that is a
  reason not to add either major version—not a reason to guess.

`net.Resolver` instances are created once per configuration generation and
egress mark, then reused concurrently. The standard library owns transport
lifetime; the daemon does not create a per-host resolver or socket pool.

## Consequences

- The bounded cache, pending limit, cancellation isolation, response classes,
  stale policy, reload generations, and multi-address retry ship without a new
  runtime dependency.
- Operator-configured TTLs are predictable but do not track authoritative DNS
  TTL changes. The defaults bound this tradeoff to five minutes.
- A future authoritative-TTL implementation must replace only the resolver
  adapter; cache and dialing policy remain unchanged.
