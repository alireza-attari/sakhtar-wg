# Release operations

Only maintainers listed in `docs/project/MAINTAINERS.md` may release. A tag must
point at a reviewed commit on the protected default branch, have a matching
changelog section, and use `vMAJOR.MINOR.PATCH`.

1. Resolve all release-blocking CI/security findings and freeze dependencies.
2. Run the full unprivileged and disposable namespace suites on the pinned Go
   toolchain; record any platform-specific evidence.
3. Move changelog entries from Unreleased to the version/date section and state
   config/state compatibility plus exact rollback behavior.
4. Review `scripts/build-release.sh`, `scripts/verify-release.sh`, Dockerfile,
   workflow permissions, and all dependency/action changes with two independent
   approvers when available.
5. Create and push the version tag. The release workflow rebuilds/tests,
   performs the reproducibility check, emits SBOM/checksums, signs and verifies
   the checksum manifest, attests artifacts and image, scans the image, verifies
   clean installation/systemd syntax, then publishes.
6. Independently download the release and run the commands in
   `docs/VERIFICATION.md`. Do not rely only on the producing workflow's checks.
7. Canary the upgrade and rollback procedure before broad rollout.

Release keys are keyless GitHub OIDC identities bound to the release workflow;
there is no long-lived repository signing key to distribute. Repository rules
must protect the workflow and default branch, restrict tag creation, require
review/status checks, and prevent force pushes. GitHub artifact attestations
for private repositories require an eligible GitHub plan; if unavailable, the
release stops until an equivalent protected provenance system is configured.

Compromised release response: stop publication, revoke/delete affected tags and
packages only after preserving forensic evidence, publish a security advisory,
rotate forge credentials/tokens, identify the last trusted provenance chain,
and cut a clean replacement version. Never silently replace assets under an
existing version.
