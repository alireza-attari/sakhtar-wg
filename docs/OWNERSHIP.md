# Host-network ownership contract

sakhtar-wg fails closed whenever it cannot attribute a host-network object to
the daemon. Run `sakhtar-wg plan -c /etc/sakhtar-wg/config.yaml` before the
first rollout and after configuration changes. The command is read-only and
prints a deterministic JSON diff without private keys, peer keys, endpoints,
or client traffic identifiers.

## Reserved allocations

The following values are the deployment reservation for every host on which
sakhtar-wg runs:

| Object | Allocation | Ownership evidence |
|---|---:|---|
| IPv4 routes | route protocol `186` | protocol + exact table/link/destination + owned link alias |
| IPv4 policy rules | priorities `31000–31999` | priority + rule protocol `186` + exact mark/mask/table |
| Marks | configured non-zero `fwmark` with an exact `0xffffffff` mask by default | config validation proves selectors do not alias |
| Route tables | configured positive IDs excluding `253`, `254`, and `255` | config validation proves uniqueness |
| WireGuard links | `sakhtar-wg:v1:<creation-policy>:<key-id>` link alias | alias, WireGuard type, and public identity derived from the configured private key |
| Firewall | `SAKHTAR_WG_*` user chains | every rule and built-in jump has a `sakhtar-wg:owned:v1` comment |

Do not assign protocol `186` or priorities `31000–31999` to NetworkManager,
systemd-networkd, routing daemons, provisioning scripts, or another
sakhtar-wg instance. Startup reports a conflict before mutation when those
allocations contain an object that does not match the desired owned tuple.

## Link creation and adoption

The default `adopt_existing: false` rejects every same-name interface that
lacks the expected alias. A name match is never ownership evidence.

`adopt_existing: true` is an explicit migration tool. Adoption succeeds only
when the object is an already-up WireGuard link, has the desired MTU, no alias,
address, route, or colliding policy rule, and its public key, peer, endpoint,
allowed IPs, and keepalive already match the desired configuration. The daemon
then writes an `adopted`
ownership alias. Down/disable removes only exact state added around an adopted
link and never deletes the link itself. A foreign alias is never overwritten.

Created links are deleted only when their key-derived alias still matches and
no foreign address or route is attached. Any ambiguous object stops deletion
and appears as cleanup drift.

## Route, rule, and firewall repair

Routes are added with `RTPROT 186`; `RouteReplace` is not used. A route with the
same table/link/destination but another protocol is blocking drift and remains
unchanged. Only exact protocol-186 tuples on an owned link are withdrawn.

Rules always specify priority, mark, mask, table, and protocol. Config loading
rejects duplicate tables, priorities, marks, selector overlap, zero values, and
reserved route-table IDs before mutation.

Gateway policy is compiled as explicit client CIDR × destination CIDR × egress
interface tuples. The forward path accepts only those tuples; return traffic
also requires `ESTABLISHED,RELATED`. TCP MSS clamp and MASQUERADE have the same
source/destination/interface scope. Terminal client and owned-destination
drops run before later built-in rules, so a foreign broad `FORWARD` accept
cannot widen the policy. `iptables-restore --noflush` flushes and
repopulates only the dedicated chains, so reload drops stale owned rules while
foreign tables/chains/rules remain intact. A reserved chain containing any
uncommented rule or a foreign built-in jump is never changed or removed.

## Sysctls

The daemon requires:

- `net.ipv4.conf.all.src_valid_mark=1` when tunnels are configured;
- `net.ipv4.ip_forward=1` when gateway mode is enabled.

It records the previous and required values in
`/run/sakhtar-wg/reconcile.json`. Global sysctls are **not restored on exit by
default**, because the daemon cannot prove exclusive ownership and restoring a
stale value could break another network component. `status` reports this as
`restore_on_exit=false`.

## Capabilities and service hardening

The supplied unit bounds the process to `CAP_NET_ADMIN` and
`CAP_NET_BIND_SERVICE`, uses `NoNewPrivileges`, a private temporary directory,
read-only system paths, address-family restrictions, and other low-risk
hardening. `CAP_NET_BIND_SERVICE` can be removed when all listeners use ports
1024 or above. The current iptables/sysctl execution model still runs as root;
the capability bound documents the intended ceiling and should be revalidated
whenever the firewall backend or systemd policy changes.

## Rollout stop conditions

Stop rollout when any of the following is true:

- the route protocol or priority range has not been reserved on the host;
- dry-run reports blocking drift;
- a same-name link cannot pass the strict ownership/adoption check;
- an integration client can forward outside a configured client/destination
  tuple;
- cleanup would delete an object without exact ownership evidence.
