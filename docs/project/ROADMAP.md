# Roadmap

This roadmap has no committed delivery dates.

## Current

- Record approved Linux amd64/arm64 performance baselines and noise bands.
- Run sustained maximum-session, unique-host, slowloris, resolver outage,
  backend outage, route reload, upgrade, rollback, and chaos scenarios.
- Review and address OpenSSF Scorecard findings.
- Obtain an external security review and remediate findings.

## Next

- Validate a non-root/user-namespace container profile and a tested systemd
  syscall allowlist without weakening netlink/WireGuard/firewall behavior.
- Publish conformance-like scenario fixtures and release-to-release upgrade
  matrices across supported kernels/distributions.
- Add maintainers as the contributor base grows.

## Later

- Evaluate PGO, buffer pooling, cache shard tuning, or alternate copy paths only
  after representative profiles identify a stable hotspot.
- Consider IPv6 gateway/pfSense routing and L3 failover through separate
  architecture/security reviews.
