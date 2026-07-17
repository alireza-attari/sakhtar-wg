# Container deployment

The release image is multi-architecture (`linux/amd64`, `linux/arm64`) and runs
as root because the current design creates kernel WireGuard links, policy
routes/rules, sysctls, and iptables state. Root is not treated as unlimited:
run with only `NET_ADMIN` and, when binding below 1024, `NET_BIND_SERVICE`.

Example shape:

```sh
docker run --rm --name sakhtar-wg \
  --network host \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /run/sakhtar-wg:rw,noexec,nosuid,nodev,mode=0700 \
  --mount type=volume,src=sakhtar-wg-state,dst=/var/lib/sakhtar-wg \
  --mount type=bind,src=/etc/sakhtar-wg/config.yaml,dst=/etc/sakhtar-wg/config.yaml,ro \
  ghcr.io/alireza-attari/sakhtar-wg:vX.Y.Z
```

Mount the config, WireGuard keys, SSH key, and pinned `known_hosts` read-only
with host mode `0600` and ownership readable only by the container process.
Never bake credentials into an image or pass them in environment variables.
Use a dedicated state volume; no other writable rootfs path is required.

User namespaces and a non-root UID are desirable, but they are not claimed as
supported until integration tests prove netlink, WireGuard, SO_MARK, sysctl,
iptables, low-port bind, and child-process capability behavior on every
supported runtime. Gateway/pfSync-disabled deployments may be able to remove
tools or capabilities, but that is a separately tested profile rather than an
implicit promise.
