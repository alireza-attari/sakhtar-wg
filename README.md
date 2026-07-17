# sakhtar-wg

[![Verification](https://github.com/alireza-attari/sakhtar-wg/actions/workflows/ci.yml/badge.svg)](https://github.com/alireza-attari/sakhtar-wg/actions/workflows/ci.yml)
[![Security](https://github.com/alireza-attari/sakhtar-wg/actions/workflows/security.yml/badge.svg)](https://github.com/alireza-attari/sakhtar-wg/actions/workflows/security.yml)
[![Release](https://github.com/alireza-attari/sakhtar-wg/actions/workflows/release.yml/badge.svg)](https://github.com/alireza-attari/sakhtar-wg/actions/workflows/release.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/alireza-attari/sakhtar-wg/badge)](https://scorecard.dev/viewer/?uri=github.com/alireza-attari/sakhtar-wg)
[![Go Reference](https://pkg.go.dev/badge/github.com/alireza-attari/sakhtar-wg.svg)](https://pkg.go.dev/github.com/alireza-attari/sakhtar-wg)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)

sakhtar-wg is a Linux networking daemon for managing multiple kernel WireGuard
tunnels and routing selected traffic through them. It supports hostname-based
proxy routing, CIDR-based gateway routing, tunnel health checks, failover groups,
remote route sources, and optional pfSense synchronization.

The project is pre-1.0. Review the configuration and ownership rules before
using it on a host that already has managed routes, policy rules, WireGuard
interfaces, or firewall state.

## How it works

- WireGuard interfaces are configured through
  [`wgctrl`](https://pkg.go.dev/golang.zx2c4.com/wireguard/wgctrl), while
  addresses, routes, and policy rules use
  [`netlink`](https://pkg.go.dev/github.com/vishvananda/netlink).
- Each tunnel has its own firewall mark and routing table. Unmarked host traffic
  continues to use the normal route table.
- The TCP proxy reads TLS SNI or an HTTP `Host` header without terminating TLS,
  selects the most-specific configured suffix, and dials the destination with
  the selected tunnel mark.
- Optional gateway mode forwards configured client and destination CIDRs through
  a tunnel with narrowly scoped firewall and NAT rules.
- Route sources refresh CIDR lists on a timer and retain the last valid result
  when a source is unavailable.
- Health checks can select the first healthy member of a tunnel group for new
  proxy connections.
- A loopback or Unix-socket management listener exposes liveness, readiness,
  Prometheus metrics, and redacted status.

```text
client
  -> source ACL
  -> bounded TLS SNI / HTTP Host parser
  -> hostname rule
  -> DNS and destination policy
  -> marked or direct connection
```

## Requirements

The production target is 64-bit Linux on `amd64` or `arm64` with:

- kernel WireGuard support;
- policy routing and `SO_MARK`;
- iproute2 and iptables;
- `CAP_NET_ADMIN`;
- `CAP_NET_BIND_SERVICE` when listening on ports below 1024.

Pure logic tests also run on macOS. Linux network effects fail closed on
unsupported platforms.

## Build

The repository uses Go 1.26.5.

```sh
make test
make build-linux
make verify-release
```

Release binaries are written to `dist/`. The Makefile also provides race,
integration, fuzz, benchmark, static analysis, and vulnerability-check targets;
see [docs/VERIFICATION.md](docs/VERIFICATION.md).

## Configuration

Copy [config.example.yaml](config.example.yaml) and replace its placeholders:

```sh
sudo install -d -m 0700 /etc/sakhtar-wg
sudo install -m 0600 config.yaml /etc/sakhtar-wg/config.yaml
```

Do not commit a deployed configuration. It contains WireGuard keys and may
contain private endpoints or SSH credentials.

Non-loopback proxy listeners require an explicit `allowed_source_cidrs` list.
Hostname rules select an egress path but do not authorize destination
addresses. Private destinations remain denied unless the relevant egress policy
explicitly allows them.

Before the first deployment, reserve route protocol `186` and policy-rule
priorities `31000-31999` for sakhtar-wg. Run a read-only plan and resolve any
ownership conflict before starting the service:

```sh
sakhtar-wg plan -c /etc/sakhtar-wg/config.yaml
```

The complete host-state ownership contract is documented in
[docs/OWNERSHIP.md](docs/OWNERSHIP.md).

## Run with systemd

After installing a release binary at `/usr/local/bin/sakhtar-wg`:

```sh
sudo install -m 0644 sakhtar-wg.service /etc/systemd/system/sakhtar-wg.service
sudo systemctl daemon-reload
sudo systemctl enable --now sakhtar-wg
```

The supplied unit limits capabilities and filesystem access. Review it against
the enabled features and the target distribution before deployment.

## CLI

```text
sakhtar-wg up      [-c config]   apply configuration and run in the foreground
sakhtar-wg down    [-c config]   remove owned tunnel state
sakhtar-wg status  [-c config]   show redacted tunnel and component status
sakhtar-wg plan    [-c config]   print the proposed host-state change
sakhtar-wg reload                reload a running process
sakhtar-wg version [-json]       print build metadata
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Host-state ownership](docs/OWNERSHIP.md)
- [Configuration compatibility](docs/project/COMPATIBILITY.md)
- [Observability](docs/OBSERVABILITY.md)
- [Container deployment](docs/CONTAINER.md)
- [Performance testing](docs/performance/README.md)
- [Verification](docs/VERIFICATION.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Release process](docs/RELEASES.md)

## Scope

Gateway routing and pfSense synchronization are currently IPv4-only. Proxy
destinations may resolve to IPv4 or IPv6. L3 failover between tunnels and the
external DNS-rewrite control plane are outside this repository.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance. Report suspected
vulnerabilities through the private process in [SECURITY.md](SECURITY.md).

sakhtar-wg is available under the [MIT License](LICENSE).
