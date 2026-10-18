# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and
versions follow Semantic Versioning.

## [Unreleased]

### Fixed

- Policy rules, routes, links, and gateway firewall rules removed by something
  outside the daemon (for example a systemd-networkd restart) are now detected
  and reapplied within 30 seconds, instead of staying missing until the next
  reload or restart while the proxy egressed via the WAN. Route-source refreshes
  also restore policy rules now, not only routes. Repairs are counted in
  `sakhtar_wg_kernel_repair_total`.
- Group failover now requires a passing active probe as well as a recent
  handshake, so a tunnel that keeps its handshake but passes no traffic is left.
  Verdicts have hysteresis and expire (`health_probe.fail_after`, default 2;
  `recover_after`, default 3; `max_age`, default 3 x interval), and
  `sakhtar_wg_group_policy_state` reports the probe-aware reason.
- A connection whose dial or DNS answer fails on one group member retries the
  next eligible member within the same `proxy.dial_timeout`, re-resolving
  through that member's resolver.
- A DNS answer made only of policy-denied addresses (for example the poisoning
  address 10.10.34.36) is no longer cached for its TTL.
- Each backend dial attempt gets a slice of the remaining dial budget, so one
  blackholed address no longer uses all of it. IPv6 candidates are no longer
  dialed through the IPv4-only tunnels.
- Active probes no longer reuse pooled connections, so every probe tests a
  fresh DNS lookup and dial through its tunnel.
- A tunnel DNS query that times out over UDP is retried over TCP to the same
  resolver within the remaining `dns_resolver_timeout`. A path that drops most
  UDP to the resolver no longer takes the tunnel's DNS down. Tunnel lookups ask
  for A records only.
- `dns_max_pending` now applies per egress. One tunnel whose resolver
  blackholes can no longer fill the shared cap and fail uncached lookups on
  every egress.
- A connection routes with the router current when it dials, not the one from
  when it was accepted, so a reload during the client's handshake cannot send
  it out a removed tunnel's mark (and so the WAN).
- A reload keeps the probe history of tunnels whose configuration did not
  change, so a tunnel failing its probe is not eligible again right after it.
- A route refresh queued during a reload no longer re-applies the pre-reload
  config. The pfSense push runs without the updater lock and is bounded to
  60s, so a stalled pfSense can no longer wedge the main loop.
- Route-source fetches close their idle connection when they return.

### Added

- `proxy.resolver` accepts a list of up to 4 resolvers, tried in order through
  each tunnel. A single string still works. `tunnels[].resolver` overrides it
  for one tunnel, and editing it on reload does not reconfigure the device.
- A tunnel DNS answer made only of policy-denied addresses (wg0's relay hijacks
  UDP/53 and answers 10.10.34.x) is retried over TCP and then on the next
  listed resolver before the egress is given up.
- `contrib/networkd.conf.d/10-sakhtar-wg.conf`, which stops systemd-networkd
  from deleting the daemon's policy rules when it restarts.

## [0.1.0] - 2026-07-17

### Added

- Bounded proxy, DNS, lifecycle, host-state ownership, observability, and
  performance tooling.
- Linux release and container workflows with checksum, SBOM, signing,
  provenance, and vulnerability-check steps.

### Changed

- Runtime files now live under `/run/sakhtar-wg/` with mode `0700`; the route
  source cache is stored with restrictive directory/file permissions.

### Security

- Added CI definitions for race tests, vulnerability and container scans,
  secret scanning, CodeQL, checksums, SBOMs, signatures, and attestations.

[Unreleased]: https://github.com/alireza-attari/sakhtar-wg/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alireza-attari/sakhtar-wg/releases/tag/v0.1.0
