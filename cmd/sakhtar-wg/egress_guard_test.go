package main

import (
	"strings"
	"testing"
)

func TestEgressGuardCoversEveryTunnelMark(t *testing.T) {
	cfg := &Config{Tunnels: []Tunnel{
		{Name: "wg0", Fwmark: 2, FwmarkMask: ^uint32(0)},
		{Name: "wgsh", Fwmark: 0x400, FwmarkMask: 0xf00},
	}}
	ruleset, err := compileEgressGuardRuleset(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ruleset.Chains) != 1 {
		t.Fatalf("chains = %d, want the guard chain only", len(ruleset.Chains))
	}
	rules := strings.Join(ruleset.Chains[0].Rules, "\n")
	for _, want := range []string{"! -o wg0 -m mark --mark 0x2 ", "! -o wgsh -m mark --mark 0x400/0xf00 "} {
		if !strings.Contains(rules, want) {
			t.Fatalf("guard lacks %q:\n%s", want, rules)
		}
	}
}

// The guard rejects marked packets that leave through anything but the
// tunnel. If WireGuard ever stamped its own encrypted UDP with the routing
// mark, those packets would leave through the WAN and every tunnel would die.
func TestWireGuardDeviceCarriesNoFirewallMark(t *testing.T) {
	cfg, err := wgConfig(Tunnel{
		Name: "wg0", PrivateKey: testKey(1), Fwmark: 2,
		Peer: Peer{PublicKey: testKey(2), Endpoint: "192.0.2.1:51820", AllowedIPs: []string{"0.0.0.0/0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FirewallMark != nil {
		t.Fatalf("WireGuard firewall mark = %d, want unset", *cfg.FirewallMark)
	}
}
