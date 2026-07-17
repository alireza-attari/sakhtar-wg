# Threat model

## Overview

sakhtar-wg is a privileged Linux networking daemon that configures kernel
WireGuard interfaces, routes, policy rules, sysctls, and optional iptables
chains; accepts unauthenticated proxy TCP connections; resolves and dials
Internet destinations with optional socket marks; fetches external route lists;
and may update one pfSense OpenVPN field over SSH. A compromise can affect host
root-equivalent network state, tunnel private keys, traffic routing and
availability, and other clients sharing the gateway.

Primary security objectives are to route only authorized source/destination
tuples, keep direct and marked egress isolated, preserve foreign host state,
bound work under malicious input, protect credentials and operational privacy,
make reload/rollback atomic, and ship artifacts whose source and dependency
chain can be verified.

## Threat Model, Trust Boundaries, and Assumptions

### Assets and privileges

- Linux `CAP_NET_ADMIN`/root authority, low-port bind authority, WireGuard
  private keys, SSH private key and pinned host identity.
- Kernel links, addresses, routes, rules, sysctls, firewall chains, and existing
  traffic belonging to this daemon or other software.
- Config integrity, route-source last-good state, runtime generation, release
  workflow identity, signing/attestation identity, and dependency set.
- Availability and confidentiality of client connections; privacy of client
  addresses, requested hostnames, resolved destinations, peer endpoints, and
  operational topology.

### Trust boundaries

1. Unauthenticated network clients cross the proxy listener boundary before
   protocol parsing. Source IP is useful only to the degree the network path
   prevents spoofing.
2. Requested SNI/Host and all subsequent bytes are attacker-controlled. A
   routing match is not destination authorization.
3. DNS resolvers and DNS answers cross an external supply-chain boundary; the
   configured resolver and egress identity affect answer meaning.
4. Operator YAML, key files, listener bindings, CIDRs, peer endpoints, route
   sources, and management settings are trusted only after strict validation
   and filesystem access control. A malicious root operator is out of scope.
5. Route-source HTTP endpoints and their bodies are untrusted even when
   configured by an operator. HTTPS trust roots and marked/direct routing are
   part of this boundary.
6. Kernel/netlink/WireGuard/iptables current state may include foreign objects.
   Object names alone never establish ownership.
7. pfSense SSH crosses a host boundary. The local daemon trusts the pinned host
   key and a forced command that only validates/updates one field; the remote
   host remains outside this repository.
8. Loopback/Unix management endpoints cross an operator boundary. Local users
   with access may see redacted state and, when explicitly enabled, expensive
   pprof data.
9. Developers, dependencies, CI actions, forge rules, OIDC identities,
   registries, and release consumers form the software supply-chain boundary.

Assumptions: the Linux kernel and Go runtime are supported and patched; the
operator protects config/key permissions and reserves documented kernel
identifiers; upstream WireGuard peers and configured DNS/pfSense endpoints are
intentionally trusted for their stated role; management is never exposed
beyond loopback/Unix access; and production tests occur only on authorized
infrastructure. Prior root, malicious kernel, physical host compromise, and
traffic analysis by an intentionally selected VPN provider are out of scope.

## Attack Surface, Mitigations, and Attacker Stories

### Proxy and protocol parsing

An Internet/LAN client may open many connections, send fragmented or malformed
TLS/HTTP, omit SNI/Host, slow-roll a header, hold a stream idle, request an IP
literal, or induce repeated backend failure. `cmd/sakhtar-wg/sni.go` checks the
source ACL before
parsing, acquires global/per-source admission before a goroutine, sets bounded
handshake/dial/idle/shutdown limits, caps ClientHello/headers, canonicalizes
hostnames, and records bounded rejection labels. Destination policy rejects
private, loopback, link-local, documentation, benchmark, multicast,
unspecified, and daemon-owned answers by default, with egress-scoped exceptions
that cannot override the strongest self/multicast/unspecified prohibitions.

Relevant vulnerability classes include ACL bypass through address parsing,
hostname boundary confusion, request smuggling into the Host parser, SSRF or
DNS rebinding past destination checks, admission races, unbounded goroutine/FD
growth, cross-generation policy confusion, deadline bypass, and shutdown leaks.
The cache key includes canonical hostname, family, egress, resolver, and
generation; allowed IPs are rechecked before dialing an IP literal.

### DNS, cache, and route sources

Attackers can generate unique hostnames to thrash cache capacity or pending
resolution slots, while a resolver can delay, fail transiently, return
NXDOMAIN/NODATA, or provide many/duplicate addresses. `internal/dns` separates
fixed positive/negative capacity, bounds pending cache-owned work, clamps TTLs,
distinguishes authoritative and transient failure, permits bounded stale data
only by policy, copies results, and limits dial candidates. Metrics never use
hostnames as labels.

A configured route source can be slow, enormous, malformed, compromised, or
temporarily unavailable. Fetches have total timeout and body size limits,
parsers retain IPv4 only, sets are normalized/deduplicated, last-good data is
kept on failure, and state writes are restrictive and atomic. Remaining risks
include a legitimately signed but malicious provider list, compromised CA/DNS,
over-broad valid CIDRs, and operator selection of insecure HTTP. Operators must
treat source changes as supply-chain events and constrain gateway clients.

### Privilege and host-network ownership

A configuration or kernel race could otherwise overwrite a foreign interface,
route, rule, firewall chain, or global sysctl. `internal/kernel`,
`internal/firewall`, and the effectors under `cmd/sakhtar-wg` use aliases,
reserved route protocol 186, exact mark/mask and priority ranges, dedicated
commented chains, collision detection, deterministic plans, and fail-closed
adoption. Global sysctls record previous/required values but are not blindly
restored because exclusive ownership cannot be proven.

Critical classes include command injection into iptables/SSH, arbitrary
netlink deletion, ownership spoofing accepted without proof, mark/mask aliasing
that leaks direct traffic into a tunnel or vice versa, and rollback that leaves
an attacker-selected route. Interface/config names and CIDRs are validated;
iptables input is compiled rather than accepting raw operator fragments; SSH
arguments are separated and the remote command is fixed.

### Keys, config, SSH, and observability

Private keys in YAML and SSH key files are operator-controlled secrets.
Config is size-bounded and strict, logs/status are redacted, metrics use fixed
or config-bounded labels, and the unit uses a read-only system filesystem,
private temp, restrictive umask/state directories, capability bounds, and
`NoNewPrivileges`. The design still runs as root and child processes inherit
the service capability ceiling; permission mistakes or a compromised daemon
therefore remain high impact.

The management endpoint is loopback/Unix-only with header/time limits. pprof is
off by default because profiles can disclose memory/topology and consume CPU;
when enabled it also collects mutex/block data. Local unprivileged users are not
assumed hostile on a dedicated host; multi-user hosts should use a mode-0600
Unix socket and filesystem authorization.

### pfSense control integration

An attacker controlling route data could try to withdraw or inject split
networks. The local side aggregates deterministic desired routes, includes
operator keep networks, refuses suspiciously small sets, sends only on change,
pins `known_hosts`, uses batch mode, and invokes a fixed `update` command. The
remote forced-command script and its validation are operational dependencies
outside this repository. A compromised pfSense or its privileged SSH account is
out of scope for code execution here but can alter downstream routing; deploy a
dedicated least-privilege key and audit remote changes.

### Release supply chain

Developer or action compromise can introduce malicious source/dependencies or
replace artifacts. CI runs race/integration/fuzz/static/vulnerability/secret
and container checks; release builds are trimpath/static with embedded
metadata, repeated for byte equality, checksummed, SBOMed, keyless-signed,
attested, and clean-image tested. Remaining controls depend on protected branch
and tag rules, independent review, OIDC and GitHub integrity, and consumers
verifying artifacts. The project currently has one maintainer, which limits
independent review.

## Severity Calibration (Critical, High, Medium, Low)

### Critical

Unauthenticated remote code execution as root; extraction of WireGuard/SSH
private keys by a network client; arbitrary foreign host-state deletion; a
source/destination policy bypass that reliably routes broad unauthorized
traffic; or compromise of the protected release identity producing apparently
valid malicious artifacts. These require realistic reachability from an
untrusted client, source, or contributor without prior root.

### High

Remote SSRF into protected networks despite default policy; cross-tunnel/direct
egress isolation failure; remotely triggerable unbounded goroutine/FD/heap
growth beyond configuration; reload/rollback corruption requiring host repair;
command injection limited by existing config write access below root; or a
signed release missing its asserted source/dependency provenance.

### Medium

Bounded but material service outage, stale/negative DNS confusion that violates
documented policy without reaching protected addresses, observability leakage
of client hostnames/addresses to authorized local operators, ownership drift
that safely blocks operation, or a pfSense update failure that retains the last
good route set. Impact and deployment exposure can raise or lower these.

### Low

Minor redaction of non-secret topology, inaccurate bounded metrics, hardening
gaps requiring an already privileged local user, documentation that could lead
an operator to an unsafe but explicitly warned deployment, or performance
degradation that remains within configured resource bounds. Pure denial of
service inside an operator-selected cap and findings requiring prior root are
normally low or out of scope unless they cross another security boundary.
