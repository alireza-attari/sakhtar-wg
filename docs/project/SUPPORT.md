# Support and platform policy

Community support is provided through the canonical issue tracker on a
best-effort basis. Include the exact `sakhtar-wg version -json` output,
sanitized config shape, Linux distribution/kernel, WireGuard implementation,
firewall backend, reproduction steps, and redacted status/metrics. Never attach
private keys, SSH keys, peer endpoints that must remain private, client
addresses, or complete production configs.

## Supported environment

The production target is 64-bit Linux on `amd64` or `arm64`, with kernel
WireGuard, netlink, policy routing, and iptables compatible with the documented
integration suite. The static binaries are tested on clean Debian 13 and Ubuntu
24.04 images for installation/startup metadata. macOS supports pure-logic unit
tests only; marked dials and kernel reconciliation fail closed there. IPv6
proxy destinations are supported, but gateway routes, aggregation, and pfSense
sync are currently IPv4-only.

Support requires an unmodified tagged binary or a reproducible build from a
known commit, a validated configuration, reserved route protocol/rule priority
ranges, and no known blocking ownership drift. Unsupported kernels,
out-of-tree firewall modifications, custom patches, and end-of-life releases
may receive guidance but are not release blockers.

Security incidents use `SECURITY.md`; do not disclose them in public support
requests.
