# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and
versions follow Semantic Versioning.

## [Unreleased]

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

Release maintainers move these entries to `## [X.Y.Z] - YYYY-MM-DD`, add
operator migration/rollback notes, and leave an empty Unreleased section before
creating a `vX.Y.Z` tag.
