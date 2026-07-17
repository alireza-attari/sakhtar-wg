//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/alireza-attari/sakhtar-wg/internal/firewall"
)

type chainInspection struct {
	Chain      firewall.Chain
	Exists     bool
	OwnedRules int
	OwnedJumps int
}

// gatewayUp atomically replaces rule bodies inside dedicated application
// chains. Built-in chains contain only one commented jump per hook.
func gatewayUp(cfg *Config) error {
	if !cfg.Gateway.Enabled {
		return nil
	}
	ruleset, err := compileGatewayRuleset(cfg)
	if err != nil {
		return err
	}
	inspections, err := inspectFirewallOwnership(ruleset)
	if err != nil {
		return err
	}
	if err := writeSysctl("net/ipv4/ip_forward", "1"); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	if err := runRestore(ruleset.RestoreInput()); err != nil {
		return fmt.Errorf("replace owned firewall ruleset: %w", err)
	}
	var applyErrors []error
	for _, inspection := range inspections {
		if inspection.OwnedJumps == 0 {
			if err := runIPTables("-t", inspection.Chain.Table, "-I", inspection.Chain.Hook, "1",
				"-m", "comment", "--comment", inspection.Chain.Comment, "-j", inspection.Chain.Name); err != nil {
				applyErrors = append(applyErrors, fmt.Errorf("install %s jump: %w", inspection.Chain.Table, err))
			}
			continue
		}
		for duplicate := inspection.OwnedJumps; duplicate > 1; duplicate-- {
			if err := deleteJump(inspection.Chain); err != nil {
				applyErrors = append(applyErrors, fmt.Errorf("deduplicate %s jump: %w", inspection.Chain.Table, err))
				break
			}
		}
	}
	return errors.Join(applyErrors...)
}

func compileGatewayRuleset(cfg *Config) (firewall.Ruleset, error) {
	policy := firewall.Policy{}
	if cfg.Gateway.Enabled {
		policy.ClientCIDRs = append([]string(nil), cfg.Gateway.ClientCIDRs...)
		for _, tunnel := range cfg.Tunnels {
			if len(tunnel.Routes) == 0 {
				continue
			}
			policy.Tunnels = append(policy.Tunnels, firewall.TunnelPolicy{
				Interface: tunnel.Name, Destinations: append([]string(nil), tunnel.Routes...),
			})
		}
	}
	ruleset, err := firewall.Compile(policy)
	if err != nil {
		return firewall.Ruleset{}, fmt.Errorf("compile gateway firewall policy: %w", err)
	}
	return ruleset, nil
}

func inspectFirewallOwnership(ruleset firewall.Ruleset) ([]chainInspection, error) {
	inspections := make([]chainInspection, 0, len(ruleset.Chains))
	for _, chain := range ruleset.Chains {
		inspection := chainInspection{Chain: chain}
		chainOutput, chainExists, err := listChain(chain.Table, chain.Name)
		if err != nil {
			return nil, err
		}
		inspection.Exists = chainExists
		if chainExists {
			for _, line := range strings.Split(chainOutput, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "-A "+chain.Name+" ") {
					continue
				}
				if !firewall.RuleIsOwned(line) {
					return nil, fmt.Errorf("%s/%s contains a rule without sakhtar-wg ownership proof", chain.Table, chain.Name)
				}
				inspection.OwnedRules++
			}
		}

		hookOutput, _, err := listChain(chain.Table, chain.Hook)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(hookOutput, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "-A "+chain.Hook+" ") || !jumpsTo(line, chain.Name) {
				continue
			}
			if !strings.Contains(line, "--comment "+chain.Comment) && !strings.Contains(line, "--comment \""+chain.Comment+"\"") {
				return nil, fmt.Errorf("%s/%s has a foreign jump to reserved chain %s", chain.Table, chain.Hook, chain.Name)
			}
			inspection.OwnedJumps++
		}
		if chainExists && inspection.OwnedRules == 0 && inspection.OwnedJumps == 0 {
			return nil, fmt.Errorf("%s/%s already exists without ownership evidence", chain.Table, chain.Name)
		}
		inspections = append(inspections, inspection)
	}
	return inspections, nil
}

func jumpsTo(rule, chain string) bool {
	fields := strings.Fields(rule)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-j" && strings.Trim(fields[i+1], "\"") == chain {
			return true
		}
	}
	return false
}

func listChain(table, chain string) (string, bool, error) {
	cmd := exec.Command("iptables", "-w", "5", "-t", table, "-S", chain)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), true, nil
	}
	message := strings.ToLower(string(output))
	if strings.Contains(message, "no chain/target/match") || strings.Contains(message, "does not exist") {
		return "", false, nil
	}
	return "", false, fmt.Errorf("iptables -t %s -S %s: %w: %s", table, chain, err, strings.TrimSpace(string(output)))
}

func runRestore(input string) error {
	cmd := exec.Command("iptables-restore", "--wait", "5", "--noflush")
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables-restore: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func runIPTables(args ...string) error {
	cmd := exec.Command("iptables", append([]string{"-w", "5"}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func deleteJump(chain firewall.Chain) error {
	return runIPTables("-t", chain.Table, "-D", chain.Hook,
		"-m", "comment", "--comment", chain.Comment, "-j", chain.Name)
}

// gatewayDown deletes only chains whose rule bodies and built-in jumps prove
// ownership. Global ip_forward is reported but intentionally not restored.
func gatewayDown(cfg *Config) error {
	ruleset, err := compileGatewayRuleset(cfg)
	if err != nil {
		return err
	}
	inspections, err := inspectFirewallOwnership(ruleset)
	if err != nil {
		return err
	}
	var cleanup []error
	for _, inspection := range inspections {
		for i := 0; i < inspection.OwnedJumps; i++ {
			if err := deleteJump(inspection.Chain); err != nil {
				cleanup = append(cleanup, fmt.Errorf("remove %s jump: %w", inspection.Chain.Table, err))
				break
			}
		}
	}
	if len(cleanup) != 0 {
		return errors.Join(cleanup...)
	}
	var transaction strings.Builder
	for _, inspection := range inspections {
		if !inspection.Exists {
			continue
		}
		fmt.Fprintf(&transaction, "*%s\n-F %s\n-X %s\nCOMMIT\n",
			inspection.Chain.Table, inspection.Chain.Name, inspection.Chain.Name)
	}
	if transaction.Len() > 0 {
		if err := runRestore(transaction.String()); err != nil {
			cleanup = append(cleanup, fmt.Errorf("delete owned firewall chains: %w", err))
		}
	}
	return errors.Join(cleanup...)
}
