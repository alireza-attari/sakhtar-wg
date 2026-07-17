# Contributing

Contributions are welcome through
[GitHub](https://github.com/alireza-attari/sakhtar-wg). By participating, you
agree to `CODE_OF_CONDUCT.md` and license your contribution under the MIT
license in `LICENSE`.

## Before opening a change

Use a public issue for feature proposals and ordinary bugs. Use the private
process in `SECURITY.md` for suspected vulnerabilities. Describe the operator
problem, supported platform, safety invariants, compatibility effect, and how
the result will be verified. Large changes should have an accepted design or
ADR before implementation.

The normal local checks are:

```sh
make test
make test-race
make benchmark-smoke
make vet
make build-linux
```

Privileged network tests must run only in the disposable namespace setup in
`docs/VERIFICATION.md`. Never point a test at production links, rules, routes,
firewall state, pfSense, DNS, or WireGuard peers.

## Pull requests

A pull request should be focused, explain failure and rollback behavior, add or
update tests, update docs/config examples, and include release notes for an
operator-visible change. Breaking config or behavior changes must follow
`docs/project/COMPATIBILITY.md`. Performance changes must link a reproducible workload,
before/after results, and relevant profiles as described in
`docs/performance/README.md`.

WireGuard, netlink, DNS, SSH, firewall, routing, cryptographic, and release-CI
changes are security-sensitive. They may not be auto-merged and must run the
relevant race, integration, and vulnerability checks. Additional review is
required when another qualified maintainer is available.

Reviewers should reject changes that weaken a bound, ACL, cancellation,
ownership, rollback, privacy, or provenance invariant merely to simplify code
or improve a benchmark.

## Dependency updates

Dependabot groups routine Go and workflow updates. Networking and crypto
dependencies are excluded from routine groups and must be reviewed
individually with upstream release notes, vulnerability impact, Linux
integration results, and rollback notes. Automatic merge is not permitted.

## Commit and release notes

Use concise imperative commits. Add user-visible changes under `Unreleased` in
`CHANGELOG.md` using Added, Changed, Deprecated, Removed, Fixed, or Security.
Do not include private report details before coordinated disclosure.
