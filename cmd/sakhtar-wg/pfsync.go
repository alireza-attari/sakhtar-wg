package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/alireza-attari/sakhtar-wg/internal/observability"
	internalroutesource "github.com/alireza-attari/sakhtar-wg/internal/routesource"
)

// PfSyncer keeps a pfSense OpenVPN server's "IPv4 Local Network(s)" in sync with
// a tunnel's effective routes, so split-tunnel VPN clients route the bypassed
// ranges into the VPN (where the auto-updating URL-Table alias steers them here).
//
// It pushes over SSH to a locked-down forced-command key. The far end script only
// ever validates the incoming CIDR list, sets that one server's local_network and
// runs openvpn_resync('server') — it never touches the filter or NAT, so the
// pfSense outage failure mode is out of reach. The REST API is unusable here: its
// OpenVPNServer model 500s (validate_interface) on a CARP-VIP-bound server.
//
// Safety:
//   - Aggregates to the minimal supernet set, so a push changes rarely and the
//     VPN-client resync is infrequent.
//   - Only sends when the aggregated set changed since the last successful push.
//   - KeepNetworks (the LAN) are always included; the far end also refuses a set
//     with fewer than a handful of entries, so a bug can't wipe the routes.
type PfSyncer struct {
	host, user, keyPath, knownHosts string
	port                            int
	keep                            []string
	last                            []string
	metrics                         *observability.Registry
}

func NewPfSyncer(c PfSync, registries ...*observability.Registry) *PfSyncer {
	port := c.SSHPort
	if port == 0 {
		port = 22
	}
	p := &PfSyncer{
		host:       c.SSHHost,
		port:       port,
		user:       c.SSHUser,
		keyPath:    c.SSHKey,
		knownHosts: c.KnownHosts,
		keep:       append([]string(nil), c.KeepNetworks...),
	}
	if len(registries) > 0 {
		p.metrics = registries[0]
	}
	return p
}

// Reconcile aggregates cidrs (+ KeepNetworks) and, if the set changed since the
// last successful push, sends it to pfSense over SSH. Best-effort: any failure is
// logged and never affects the tunnel or the local L3 routes.
func (p *PfSyncer) Reconcile(ctx context.Context, cidrs []string) {
	desired := p.desired(cidrs)
	if len(desired) < 5 {
		if p.metrics != nil {
			p.metrics.RecordPfSync("rejected", fmt.Errorf("minimum network guard rejected %d entries", len(desired)))
		}
		log.Printf("pfsync: refusing to push only %d nets (guard)", len(desired))
		return
	}
	if equalStrings(p.last, desired) {
		if p.metrics != nil {
			p.metrics.RecordPfSync("skipped")
		}
		return
	}
	out, err := p.push(ctx, strings.Join(desired, ","))
	if err != nil {
		if p.metrics != nil {
			p.metrics.RecordPfSync("failure", err)
		}
		log.Printf("pfsync: ssh push failed: %v (%s)", err, out)
		return
	}
	if strings.HasPrefix(out, "ERR") {
		if p.metrics != nil {
			p.metrics.RecordPfSync("rejected", fmt.Errorf("remote rejected update: %s", out))
		}
		log.Printf("pfsync: remote rejected: %s", out)
		return
	}
	p.last = desired
	if p.metrics != nil {
		p.metrics.RecordPfSync("success")
	}
	log.Printf("pfsync: %s (pushed %d nets)", out, len(desired))
}

func (p *PfSyncer) desired(cidrs []string) []string {
	in := make([]string, 0, len(cidrs)+len(p.keep))
	in = append(in, p.keep...)
	in = append(in, cidrs...)
	return aggregateIPv4(in)
}

// push sends the CSV on stdin to the forced-command key. The requested command
// ("update") is ignored by the far end; only stdin is read.
func (p *PfSyncer) push(ctx context.Context, csv string) (string, error) {
	args := []string{
		"-i", p.keyPath,
		"-p", fmt.Sprintf("%d", p.port),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=10",
	}
	if p.knownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+p.knownHosts)
	}
	args = append(args, p.user+"@"+p.host, "update")
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = strings.NewReader(csv)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// --- IPv4 CIDR aggregation (minimal covering prefix set, like collapse_addresses) ---

func aggregateIPv4(cidrs []string) []string {
	return internalroutesource.AggregateIPv4(cidrs)
}
