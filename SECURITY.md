# Security policy

sakhtar-wg is a privileged networking daemon. Treat suspected bypasses of its
source ACL, destination policy, host-state ownership checks, route isolation,
or secret handling as security issues even when no memory corruption is
involved.

## Supported versions

Until the first stable release, only the newest tagged `0.x` release is
supported. After `v1.0.0`, the current minor release and the immediately prior
minor release receive security fixes. Unsupported releases may receive a
coordinated disclosure notice but are not guaranteed patches. See
`docs/project/VERSIONING.md` for compatibility and deprecation rules.

## Reporting privately

Use
[GitHub private vulnerability reporting](https://github.com/alireza-attari/sakhtar-wg/security/advisories/new).
Do not open a public issue, paste logs containing keys, or test against
infrastructure you do not own. Include the affected version or commit,
deployment shape, preconditions, impact, reproduction steps, and a safe proof
of concept when available.

Maintainers will target:

- acknowledgement within two business days;
- initial severity and scope assessment within five business days;
- a remediation or mitigation target within seven days for critical issues,
  30 days for high issues, and the next planned release for medium/low issues;
- coordinated disclosure after supported users have a reasonable update
  window, normally no more than 90 days unless active exploitation warrants an
  earlier advisory.

These are response objectives, not a warranty. If staffing prevents a target,
the reporter will receive an updated timeline. Maintainers will request a CVE
when ecosystem impact justifies one and will credit reporters who consent.

## Security invariants

- Unauthenticated clients must pass a source CIDR ACL before parsing and must
  remain within global/per-source connection limits.
- Hostname routing selects egress; it never authorizes a destination address.
- Resolved IP literals must pass the egress-scoped destination policy, and
  daemon-owned, unspecified, and multicast addresses remain forbidden.
- Protocol reads, DNS work, connection attempts, route-source bodies, config
  size, caches, pending work, and shutdown are bounded.
- Foreign links, routes, rules, firewall rules, and sysctls must not be adopted,
  overwritten, or removed without exact ownership evidence.
- Configured private keys, SSH keys, peer identities, client addresses,
  hostnames, and destinations must not appear in metrics or routine logs.
- A rejected reload must preserve the active generation and its host state;
  successful reloads without listener changes must not interrupt sessions.
- Release artifacts are publishable only after tests, scans, checksums, SBOM,
  signature, and provenance checks pass.

The repository threat model is in `docs/security/THREAT_MODEL.md`.

## Out of scope and safe research

Denial of service that stays within an operator's explicitly configured limits,
attacks requiring prior root on the host, compromise of an intentionally
trusted WireGuard provider, and findings only in unsupported versions are
normally not vulnerabilities in this project. They may still be valuable
hardening reports. Do not scan third-party endpoints, disrupt production
traffic, access other users' data, or retain secrets encountered accidentally.
