# Versioning and release policy

sakhtar-wg uses Semantic Versioning. Tags and displayed versions are
`vMAJOR.MINOR.PATCH`; release workflow inputs must resolve to an annotated or
lightweight tag on the exact source commit.

- PATCH fixes compatible behavior, security, packaging, or documentation.
- MINOR adds backward-compatible config fields or capabilities. Before v1.0,
  a minor may contain a documented breaking change when no safe transition is
  possible.
- MAJOR may remove deprecated behavior or change config/state semantics.

Every release has changelog notes, static Linux amd64/arm64 binaries, embedded
version metadata, checksums, SPDX JSON SBOMs, a Sigstore bundle, provenance
attestations, and a multi-architecture container digest. A release is stopped
if required tests, scans, reproducibility, signing, attestation, SBOM, clean
installation, or artifact verification fails.

Config additions default safely. Deprecations remain for at least one minor
release after v1.0 and emit an actionable warning before removal. Each breaking
change states affected fields/state, preflight, migration, rollback, and the
last compatible version in `../../CHANGELOG.md` and `COMPATIBILITY.md`.

Rollback is supported only when the older version understands the on-disk
state and config. Operators must retain the previous verified binary and config
and run `plan` before both upgrade and rollback. Releases never silently
downgrade or rewrite config files.
