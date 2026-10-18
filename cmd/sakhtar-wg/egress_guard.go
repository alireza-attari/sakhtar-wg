package main

import (
	"fmt"

	"github.com/alireza-attari/sakhtar-wg/internal/firewall"
)

// compileEgressGuardRuleset pins every tunnel mark to its own interface. It is
// installed whether or not the gateway is enabled: the proxy, its DNS and the
// probes are what stamp tunnel marks, and they leak out the WAN the moment a
// tunnel's policy rule or table route goes missing.
func compileEgressGuardRuleset(cfg *Config) (firewall.Ruleset, error) {
	guards := make([]firewall.MarkGuard, 0, len(cfg.Tunnels))
	for _, tunnel := range cfg.Tunnels {
		guards = append(guards, firewall.MarkGuard{Interface: tunnel.Name, Mark: uint32(tunnel.Fwmark), Mask: tunnel.FwmarkMask})
	}
	chain, err := firewall.CompileEgressGuard(guards)
	if err != nil {
		return firewall.Ruleset{}, fmt.Errorf("compile egress guard: %w", err)
	}
	return firewall.Ruleset{Chains: []firewall.Chain{chain}}, nil
}
