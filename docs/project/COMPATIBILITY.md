# Compatibility and migration policy

## Configuration

Configuration is strict YAML: unknown fields, duplicate keys, trailing
documents, invalid identities, overlapping ownership allocations, and unsafe
listener policy are rejected before host mutation. Adding an optional field is
backward-compatible when its zero value preserves the previous safe behavior.
Changing a default, field meaning, accepted value, or persisted-state format is
breaking unless both forms can coexist through a documented transition.

A rejected startup or reload must not partially activate candidate config. A
successful reload may change routing, health, DNS generation, route sources,
and policy without interrupting established proxy connections; listener and
management-listener changes require restart. The daemon never rewrites the
operator's config.

## State and host ownership

Persisted route-source data lives at `/var/lib/sakhtar-wg/routes.json`; runtime
PID/reconciliation data lives under `/run/sakhtar-wg/`. State formats must be
forward-readable for at least the supported rollback window or the release
must provide an offline migration and backup procedure. Kernel objects are
compatible only when their aliases, route protocol, rule marks/masks,
priorities, tables, and firewall ownership comments satisfy
`docs/OWNERSHIP.md`.

The current layout moves the legacy `/run/sakhtar-wg.pid` and
`/run/sakhtar-wg-reconcile.json` files into the systemd-managed
`/run/sakhtar-wg/` directory. They are ephemeral: stop the old service, install
the new unit and binary together, run `systemctl daemon-reload`, then start.
Rollback requires stopping the new service and installing the old unit/binary;
stale runtime files may be removed only while no instance is running.

## Upgrade procedure

1. Verify checksums, Sigstore bundle, provenance, SBOM, and embedded metadata.
2. Back up config and `/var/lib/sakhtar-wg`; retain the prior verified binary
   and unit.
3. Read every intervening changelog entry and apply migrations.
4. Run the new binary's `plan -c ...`; stop on blocking drift.
5. Upgrade one canary, verify readiness, routing/DNS/proxy scenarios, reload,
   and sustained metrics, then roll out gradually.

## Rollback procedure

Drain or stop the new daemon, restore the compatible config/state and prior
binary/unit, run the prior `plan`, then start and verify readiness. Never run
two versions concurrently or manually delete links/routes/rules to force a
rollback. If the older binary cannot read the state format, follow the release's
explicit reverse migration; absence of one is a rollback stop condition.
