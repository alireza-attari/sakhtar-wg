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

### Added

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
