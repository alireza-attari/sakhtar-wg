//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	kernelstate "github.com/alireza-attari/sakhtar-wg/internal/kernel"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type firewallPlanOperation struct {
	Action string `json:"action"`
	Object string `json:"object"`
}

type sysctlPlanOperation struct {
	Key             string `json:"key"`
	Current         string `json:"current"`
	Required        string `json:"required"`
	RestoreOnExit   bool   `json:"restore_on_exit"`
	OwnershipReason string `json:"ownership_reason"`
}

type dryRunPlan struct {
	Kernel   kernelstate.Plan        `json:"kernel"`
	Firewall []firewallPlanOperation `json:"firewall_operations"`
	Sysctls  []sysctlPlanOperation   `json:"sysctls"`
}

func runPlan(path string) {
	cfg, err := LoadConfig(path)
	if err != nil {
		fatalPlan(err)
	}
	wg, err := wgctrl.New()
	if err != nil {
		fatalPlan(fmt.Errorf("open wgctrl: %w", err))
	}
	defer wg.Close()

	kernelPlan, err := buildKernelPlan(wg, cfg)
	if err != nil {
		fatalPlan(err)
	}
	firewallPlan, err := buildFirewallPlan(cfg)
	if err != nil {
		fatalPlan(err)
	}
	plan := dryRunPlan{Kernel: kernelPlan, Firewall: firewallPlan, Sysctls: buildSysctlPlan(cfg)}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plan); err != nil {
		fatalPlan(fmt.Errorf("encode plan: %w", err))
	}
}

func fatalPlan(err error) {
	fmt.Fprintf(os.Stderr, "sakhtar-wg: plan: %v\n", err)
	os.Exit(1)
}

func buildKernelPlan(wg wireGuardConfigurer, cfg *Config) (kernelstate.Plan, error) {
	var current, desired []kernelstate.Object
	var observedDrift []kernelstate.Drift
	desiredNames := make(map[string]bool, len(cfg.Tunnels))
	for _, tunnel := range cfg.Tunnels {
		desiredNames[tunnel.Name] = true
		link, found, err := lookupLink(tunnel.Name)
		if err != nil {
			return kernelstate.Plan{}, err
		}
		linkOwned := false
		linkValue := fmt.Sprintf("type=wireguard,mtu=%d,configuration=desired", tunnel.MTU)
		desiredLink := kernelstate.Object{
			Kind: kernelstate.Link, ID: tunnel.Name, Value: linkValue, Owned: true,
			Evidence: "key-derived sakhtar-wg link alias",
		}
		if found {
			_, ownershipErr := ownedLinkMode(link, tunnel)
			linkOwned = ownershipErr == nil && link.Type() == "wireguard"
			configMatches := false
			if link.Type() == "wireguard" {
				device, deviceErr := wg.Device(tunnel.Name)
				if deviceErr != nil {
					return kernelstate.Plan{}, fmt.Errorf("%s: inspect wireguard config: %w", tunnel.Name, deviceErr)
				}
				configMatches, err = deviceMatchesTunnel(device, tunnel)
				if err != nil {
					return kernelstate.Plan{}, err
				}
			}
			currentValue := fmt.Sprintf("type=%s,mtu=%d,configuration=drifted", link.Type(), link.Attrs().MTU)
			if linkOwned && configMatches {
				currentValue = linkValue
			}
			if !linkOwned && tunnel.AdoptExisting {
				if err := verifyAdoptionCandidate(wg, link, tunnel); err == nil {
					desiredLink.AllowAdopt = true
					currentValue = linkValue
				}
			}
			current = append(current, kernelstate.Object{
				Kind: kernelstate.Link, ID: tunnel.Name, Value: currentValue,
				Owned: linkOwned, Evidence: linkOwnershipEvidence(link, tunnel),
			})

			addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err != nil {
				return kernelstate.Plan{}, fmt.Errorf("%s: list addresses for plan: %w", tunnel.Name, err)
			}
			for _, address := range addresses {
				if address.IPNet == nil {
					continue
				}
				addressValue := addressKey(address.IPNet)
				id := tunnel.Name + "/" + addressValue
				owned := linkOwned && addressValue == canonicalAddress(tunnel.Address)
				current = append(current, kernelstate.Object{
					Kind: kernelstate.Address, ID: id, Value: addressValue, Owned: owned,
					Evidence: ownedEvidence(owned, "exact configured address on owned link"),
				})
				if linkOwned && !owned {
					observedDrift = append(observedDrift, kernelstate.Drift{
						Kind: kernelstate.Address, ID: id, Blocking: false,
						Reason: "unattributed address on owned link is preserved",
					})
				}
			}

			desiredAddress, _ := netlink.ParseAddr(tunnel.Address)
			routes, err := listAllRoutesOnLink(link, netlink.FAMILY_V4)
			if err != nil {
				return kernelstate.Plan{}, fmt.Errorf("%s: list routes for plan: %w", tunnel.Name, err)
			}
			for _, route := range routes {
				ownedPolicyRoute := linkOwned && int(route.Protocol) == kernelstate.RouteProtocol && route.Table != mainTable
				if route.Table != mainTable && route.Table != tunnel.Table && !ownedPolicyRoute {
					continue
				}
				if addressGeneratedRoute(route, desiredAddress) {
					continue
				}
				id := plannedRouteID(tunnel.Name, route.Table, routeDestination(route))
				owned := linkOwned && int(route.Protocol) == kernelstate.RouteProtocol
				current = append(current, kernelstate.Object{
					Kind: kernelstate.Route, ID: id, Value: fmt.Sprintf("protocol=%d", route.Protocol), Owned: owned,
					Evidence: ownedEvidence(owned, fmt.Sprintf("route protocol %d + owned link alias", kernelstate.RouteProtocol)),
				})
				if linkOwned && !owned {
					observedDrift = append(observedDrift, kernelstate.Drift{
						Kind: kernelstate.Route, ID: id, Blocking: false,
						Reason: "foreign route on owned link is preserved",
					})
				}
			}
		}
		desired = append(desired, desiredLink, kernelstate.Object{
			Kind: kernelstate.Address, ID: tunnel.Name + "/" + canonicalAddress(tunnel.Address),
			Value: canonicalAddress(tunnel.Address), Owned: true, Evidence: "exact configured address on owned link",
		})
		desired = append(desired, desiredRouteObject(tunnel.Name, tunnel.Table, "0.0.0.0/0"))
		for _, route := range tunnel.Routes {
			desired = append(desired, desiredRouteObject(tunnel.Name, mainTable, canonicalCIDR(route)))
		}
	}

	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return kernelstate.Plan{}, fmt.Errorf("list policy rules for plan: %w", err)
	}
	for _, tunnel := range cfg.Tunnels {
		desiredRule := markRule(tunnel)
		desired = append(desired, kernelstate.Object{
			Kind: kernelstate.Rule, ID: fmt.Sprintf("priority=%d", tunnel.RulePriority),
			Value: plannedRuleValue(*desiredRule), Owned: true,
			Evidence: fmt.Sprintf("reserved priority + rule protocol %d", kernelstate.RouteProtocol),
		})
		for _, rule := range rules {
			if rule.Priority != tunnel.RulePriority {
				continue
			}
			owned := int(rule.Protocol) == kernelstate.RouteProtocol
			current = append(current, kernelstate.Object{
				Kind: kernelstate.Rule, ID: fmt.Sprintf("priority=%d", rule.Priority),
				Value: plannedRuleValue(rule), Owned: owned,
				Evidence: ownedEvidence(owned, fmt.Sprintf("reserved priority + rule protocol %d", kernelstate.RouteProtocol)),
			})
		}
	}
	links, err := netlink.LinkList()
	if err != nil {
		return kernelstate.Plan{}, fmt.Errorf("list links for stale ownership markers: %w", err)
	}
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Alias, linkAliasPrefix) && !desiredNames[link.Attrs().Name] {
			observedDrift = append(observedDrift, kernelstate.Drift{
				Kind: kernelstate.Link, ID: link.Attrs().Name, Blocking: false,
				Reason: "owned marker is not in desired config; cleanup requires the last owning config",
			})
		}
	}
	plan, err := kernelstate.PlanDiff(current, desired)
	if err != nil {
		return kernelstate.Plan{}, err
	}
	driftKeys := make(map[string]bool, len(plan.Drift))
	for _, drift := range plan.Drift {
		driftKeys[string(drift.Kind)+":"+drift.ID] = true
	}
	for _, drift := range observedDrift {
		key := string(drift.Kind) + ":" + drift.ID
		if !driftKeys[key] {
			plan.Drift = append(plan.Drift, drift)
			driftKeys[key] = true
		}
	}
	sort.Slice(plan.Drift, func(i, j int) bool {
		if plan.Drift[i].Kind == plan.Drift[j].Kind {
			return plan.Drift[i].ID < plan.Drift[j].ID
		}
		return plan.Drift[i].Kind < plan.Drift[j].Kind
	})
	return plan, nil
}

func desiredRouteObject(name string, table int, destination string) kernelstate.Object {
	return kernelstate.Object{
		Kind: kernelstate.Route, ID: plannedRouteID(name, table, destination),
		Value: fmt.Sprintf("protocol=%d", kernelstate.RouteProtocol), Owned: true,
		Evidence: fmt.Sprintf("route protocol %d + owned link alias", kernelstate.RouteProtocol),
	}
}

func plannedRouteID(name string, table int, destination string) string {
	return fmt.Sprintf("table=%d/link=%s/dst=%s", table, name, destination)
}

func plannedRuleValue(rule netlink.Rule) string {
	return fmt.Sprintf("mark=%#x/%#x,table=%d,protocol=%d", rule.Mark, ruleMask(rule.Mask), rule.Table, rule.Protocol)
}

func canonicalCIDR(raw string) string {
	_, prefix, err := net.ParseCIDR(raw)
	if err != nil {
		return raw
	}
	return prefix.String()
}

func canonicalAddress(raw string) string {
	ip, prefix, err := net.ParseCIDR(raw)
	if err != nil {
		return raw
	}
	ones, _ := prefix.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), ones)
}

func linkOwnershipEvidence(link netlink.Link, tunnel Tunnel) string {
	if _, err := ownedLinkMode(link, tunnel); err == nil {
		return "key-derived sakhtar-wg link alias"
	}
	return ""
}

func ownedEvidence(owned bool, evidence string) string {
	if owned {
		return evidence
	}
	return ""
}

func buildFirewallPlan(cfg *Config) ([]firewallPlanOperation, error) {
	ruleset, err := compileGatewayRuleset(cfg)
	if err != nil {
		return nil, err
	}
	inspections, err := inspectFirewallOwnership(ruleset)
	if err != nil {
		return nil, err
	}
	var operations []firewallPlanOperation
	for _, inspection := range inspections {
		currentRules := map[string]struct{}{}
		if inspection.Exists {
			output, _, err := listChain(inspection.Chain.Table, inspection.Chain.Name)
			if err != nil {
				return nil, err
			}
			prefix := "-A " + inspection.Chain.Name + " "
			for _, line := range strings.Split(output, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, prefix) {
					currentRules[canonicalFirewallRule(strings.TrimPrefix(line, prefix))] = struct{}{}
				}
			}
		} else if cfg.Gateway.Enabled {
			operations = append(operations, firewallPlanOperation{Action: "add", Object: inspection.Chain.Table + "/" + inspection.Chain.Name})
		}
		desiredRules := map[string]struct{}{}
		if cfg.Gateway.Enabled {
			for _, rule := range inspection.Chain.Rules {
				desiredRules[canonicalFirewallRule(rule)] = struct{}{}
			}
		}
		for rule := range desiredRules {
			if _, exists := currentRules[rule]; !exists {
				operations = append(operations, firewallPlanOperation{Action: "add", Object: inspection.Chain.Table + "/" + inspection.Chain.Name + "/" + rule})
			}
		}
		for rule := range currentRules {
			if _, exists := desiredRules[rule]; !exists {
				operations = append(operations, firewallPlanOperation{Action: "delete", Object: inspection.Chain.Table + "/" + inspection.Chain.Name + "/" + rule})
			}
		}
		wantJump := 0
		if cfg.Gateway.Enabled {
			wantJump = 1
		}
		for i := inspection.OwnedJumps; i < wantJump; i++ {
			operations = append(operations, firewallPlanOperation{Action: "add", Object: inspection.Chain.Table + "/" + inspection.Chain.Hook + "/owned-jump"})
		}
		for i := wantJump; i < inspection.OwnedJumps; i++ {
			operations = append(operations, firewallPlanOperation{Action: "delete", Object: inspection.Chain.Table + "/" + inspection.Chain.Hook + "/owned-jump"})
		}
		if !cfg.Gateway.Enabled && inspection.Exists {
			operations = append(operations, firewallPlanOperation{Action: "delete", Object: inspection.Chain.Table + "/" + inspection.Chain.Name})
		}
	}
	sort.Slice(operations, func(i, j int) bool {
		if operations[i].Object == operations[j].Object {
			return operations[i].Action < operations[j].Action
		}
		return operations[i].Object < operations[j].Object
	})
	return operations, nil
}

func canonicalFirewallRule(rule string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(rule, "\"", "")), " ")
}

func buildSysctlPlan(cfg *Config) []sysctlPlanOperation {
	required := map[string]string{}
	if len(cfg.Tunnels) > 0 {
		required["net/ipv4/conf/all/src_valid_mark"] = "1"
	}
	if cfg.Gateway.Enabled {
		required["net/ipv4/ip_forward"] = "1"
	}
	keys := make([]string, 0, len(required))
	for key := range required {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]sysctlPlanOperation, 0, len(keys))
	for _, key := range keys {
		current := "unreadable"
		if raw, err := os.ReadFile("/proc/sys/" + key); err == nil {
			current = strings.TrimSpace(string(raw))
		}
		result = append(result, sysctlPlanOperation{
			Key: key, Current: current, Required: required[key], RestoreOnExit: false,
			OwnershipReason: "global sysctl ownership is not exclusive; previous value is recorded but not restored",
		})
	}
	return result
}
