# Verification

The production target is Linux with kernel WireGuard, policy routing, iptables,
and `SO_MARK`. Pure configuration, routing, DNS, proxy, health, and route-source
logic is also tested on macOS.

The repository pins Go 1.26.5. Use that version for the complete verification
target.

## Local checks

```sh
make test
make test-race
make benchmark-smoke
make vet
make build-linux
make verify-release
```

`make verify` runs the full unprivileged suite, including fuzz smoke tests,
staticcheck, govulncheck, release builds, and reproducibility checks. It installs
pinned analysis tools under the ignored `.tools/` directory.

```sh
make verify
```

The individual targets are useful when working on a focused change:

| Target | Purpose |
| --- | --- |
| `make test` | Unit and behavior tests |
| `make test-race` | Go race detector |
| `make proxy-load` | Admission, release, and graceful-drain checks |
| `make benchmark-smoke` | Compile and execute each benchmark once |
| `make benchmark` | Eight samples of each microbenchmark |
| `make fuzz-smoke` | Short run of every fuzz target |
| `make vet` | Native and Linux `go vet` |
| `make staticcheck` | Pinned staticcheck |
| `make vuln` | Pinned govulncheck |
| `make build-linux` | Static Linux amd64 and arm64 binaries |
| `make verify-release` | Metadata, checksum, and reproducibility checks |

Generated binaries, tools, profiles, and load-test output are ignored by Git.
Use `make clean` to remove them.

## Privileged integration tests

The integration suite creates WireGuard links, routes, policy rules, and
firewall state. Run it only on a disposable Linux host or CI runner.

```sh
sudo apt-get install iproute2 iptables wireguard-tools
sudo modprobe wireguard
sudo -E go test -tags=integration -count=1 -timeout=2m ./...
```

The tests use disposable network namespaces whose names start with
`sakhtar-wg-`. They must never run against production links, routes, firewall
state, pfSense instances, or WireGuard peers.

The suite covers:

- idempotent link, address, route, rule, and firewall application;
- preservation of foreign same-name links and foreign routes;
- strict adoption and cleanup ownership;
- route protocol and policy-rule selectors;
- gateway forwarding limited to configured source and destination CIDRs;
- marked TCP and DNS traffic through isolated namespace fixtures;
- cleanup after success and test failure.

## Fuzz targets

The checked-in fuzz seeds cover:

- TLS ClientHello and SNI parsing;
- HTTP request and `Host` parsing;
- strict YAML configuration loading;
- line-based CIDR sources;
- RIPE announced-prefix JSON;
- IPv4 CIDR aggregation.

Increase `FUZZ_TIME` for longer local runs:

```sh
make fuzz-smoke FUZZ_TIME=60s
```

## Continuous integration

GitHub Actions runs unit and race tests on Linux and macOS, Linux builds and
vet, fuzz smoke tests, pinned static analysis, govulncheck, and the disposable
network-namespace integration suite. Separate workflows run CodeQL, Gitleaks,
Trivy, and OpenSSF Scorecard.

The workflow definitions describe the intended checks. Use the status of the
current GitHub commit as the source of truth for whether they passed.

## Release artifacts

After downloading all assets for a release into one directory:

```sh
shasum -a 256 -c SHA256SUMS
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp='https://github.com/alireza-attari/sakhtar-wg/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  SHA256SUMS
gh attestation verify sakhtar-wg-linux-amd64 --repo alireza-attari/sakhtar-wg
gh attestation verify sakhtar-wg-linux-arm64 --repo alireza-attari/sakhtar-wg
./sakhtar-wg-linux-amd64 version -json
```

Verify the displayed version, commit, build date, toolchain, architecture, SBOM,
signature identity, and release notes before installation.
