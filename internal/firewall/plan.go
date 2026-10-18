// Package firewall compiles the gateway policy into application-owned
// iptables chains. It does not mutate built-in chains or execute commands.
package firewall

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	OwnerComment = "sakhtar-wg:owned:v1"

	FilterChain = "SAKHTAR_WG_FORWARD"
	NATChain    = "SAKHTAR_WG_POSTROUTING"
	MangleChain = "SAKHTAR_WG_FORWARD"
	OutputChain = "SAKHTAR_WG_OUTPUT"
)

type TunnelPolicy struct {
	Interface    string
	Destinations []string
}

type Policy struct {
	ClientCIDRs []string
	Tunnels     []TunnelPolicy
}

type Chain struct {
	Table   string   `json:"table"`
	Hook    string   `json:"hook"`
	Name    string   `json:"name"`
	Comment string   `json:"comment"`
	Rules   []string `json:"rules"`
}

type Ruleset struct {
	Chains []Chain `json:"chains"`
}

// Compile creates a fail-closed policy: a client/destination/interface tuple
// must be explicitly configured for forward, return, MSS clamp, and NAT.
func Compile(policy Policy) (Ruleset, error) {
	clients, err := canonicalPrefixes(policy.ClientCIDRs)
	if err != nil {
		return Ruleset{}, fmt.Errorf("client CIDRs: %w", err)
	}
	tunnels := append([]TunnelPolicy(nil), policy.Tunnels...)
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].Interface < tunnels[j].Interface })

	filter := Chain{Table: "filter", Hook: "FORWARD", Name: FilterChain, Comment: OwnerComment + ":filter-forward"}
	nat := Chain{Table: "nat", Hook: "POSTROUTING", Name: NATChain, Comment: OwnerComment + ":nat-postrouting"}
	mangle := Chain{Table: "mangle", Hook: "FORWARD", Name: MangleChain, Comment: OwnerComment + ":mangle-forward"}
	seenInterface := map[string]struct{}{}
	type destinationOwner struct {
		prefix        netip.Prefix
		interfaceName string
	}
	var destinationOwners []destinationOwner
	var destinationDrops []string
	for _, tunnel := range tunnels {
		if err := validInterface(tunnel.Interface); err != nil {
			return Ruleset{}, err
		}
		if _, duplicate := seenInterface[tunnel.Interface]; duplicate {
			return Ruleset{}, fmt.Errorf("duplicate tunnel interface %q", tunnel.Interface)
		}
		seenInterface[tunnel.Interface] = struct{}{}
		destinations, err := canonicalPrefixes(tunnel.Destinations)
		if err != nil {
			return Ruleset{}, fmt.Errorf("tunnel %s destinations: %w", tunnel.Interface, err)
		}
		for _, destination := range destinations {
			prefix := netip.MustParsePrefix(destination)
			for _, owner := range destinationOwners {
				if owner.interfaceName != tunnel.Interface && owner.prefix.Overlaps(prefix) {
					return Ruleset{}, fmt.Errorf("destination %s on %s overlaps %s on %s", prefix, tunnel.Interface, owner.prefix, owner.interfaceName)
				}
			}
			destinationOwners = append(destinationOwners, destinationOwner{prefix: prefix, interfaceName: tunnel.Interface})
			destinationDrops = append(destinationDrops,
				fmt.Sprintf("-d %s -o %s -m comment --comment %s -j DROP", destination, tunnel.Interface, OwnerComment))
		}
		for _, client := range clients {
			for _, destination := range destinations {
				owner := "-m comment --comment " + OwnerComment
				filter.Rules = append(filter.Rules,
					fmt.Sprintf("-s %s -d %s -o %s %s -j ACCEPT", client, destination, tunnel.Interface, owner),
					fmt.Sprintf("-s %s -d %s -i %s -m conntrack --ctstate RELATED,ESTABLISHED %s -j ACCEPT", destination, client, tunnel.Interface, owner),
				)
				nat.Rules = append(nat.Rules,
					fmt.Sprintf("-s %s -d %s -o %s %s -j MASQUERADE", client, destination, tunnel.Interface, owner))
				mangle.Rules = append(mangle.Rules,
					fmt.Sprintf("-s %s -d %s -o %s -p tcp -m tcp --tcp-flags SYN,RST SYN %s -j TCPMSS --clamp-mss-to-pmtu", client, destination, tunnel.Interface, owner))
			}
		}
	}
	for _, chain := range []*Chain{&filter, &nat, &mangle} {
		sort.Strings(chain.Rules)
	}
	// The jump is inserted at the beginning of FORWARD. Terminal client-scoped
	// drops prevent a later foreign/broad built-in rule from forwarding a tuple
	// outside this policy, without changing traffic unrelated to client CIDRs.
	for _, client := range clients {
		owner := "-m comment --comment " + OwnerComment
		filter.Rules = append(filter.Rules,
			fmt.Sprintf("-s %s %s -j DROP", client, owner),
			fmt.Sprintf("-d %s %s -j DROP", client, owner),
		)
	}
	sort.Strings(destinationDrops)
	filter.Rules = append(filter.Rules, destinationDrops...)
	return Ruleset{Chains: []Chain{filter, nat, mangle}}, nil
}

func validInterface(name string) error {
	if name == "" || strings.ContainsAny(name, " \t\r\n\"'") {
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
}

// MarkGuard is one tunnel's routing selector: sockets carrying Mark under Mask
// must leave through Interface and nowhere else.
type MarkGuard struct {
	Interface string
	Mark      uint32
	Mask      uint32
}

// CompileEgressGuard makes marked egress fail closed. A tunnel mark only
// reaches its tunnel through an `ip rule` and a route in the tunnel's table;
// when either is gone (systemd-networkd flushes foreign rules) the lookup
// falls through to the main table and the packet leaves the WAN. The rules
// match on the output interface the kernel already chose, so they are inert
// while routing is intact and reject only a marked packet routed anywhere but
// its own tunnel. REJECT rather than DROP so the dial fails at once and the
// probe and per-connection failover move to the next member.
//
// Loopback returns first: the local table answers before any policy rule, so
// a marked socket to a local address is not a leak.
func CompileEgressGuard(guards []MarkGuard) (Chain, error) {
	owner := "-m comment --comment " + OwnerComment
	chain := Chain{Table: "filter", Hook: "OUTPUT", Name: OutputChain, Comment: OwnerComment + ":filter-output"}
	if len(guards) == 0 {
		return chain, nil
	}
	sorted := append([]MarkGuard(nil), guards...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Interface < sorted[j].Interface })
	chain.Rules = append(chain.Rules, fmt.Sprintf("-o lo %s -j RETURN", owner))
	for i, guard := range sorted {
		if err := validInterface(guard.Interface); err != nil {
			return Chain{}, err
		}
		if i > 0 && sorted[i-1].Interface == guard.Interface {
			return Chain{}, fmt.Errorf("duplicate tunnel interface %q", guard.Interface)
		}
		if guard.Mark == 0 || guard.Mask == 0 || guard.Mark&guard.Mask != guard.Mark {
			return Chain{}, fmt.Errorf("tunnel %s: mark %#x/%#x cannot select its own traffic", guard.Interface, guard.Mark, guard.Mask)
		}
		chain.Rules = append(chain.Rules, fmt.Sprintf("! -o %s -m mark --mark %s %s -j REJECT --reject-with icmp-port-unreachable",
			guard.Interface, markSelector(guard.Mark, guard.Mask), owner))
	}
	return chain, nil
}

// markSelector renders a mark the way `iptables -S` prints it, so drift
// detection compares equal strings: the mask is shown only when not full.
func markSelector(mark, mask uint32) string {
	if mask == ^uint32(0) {
		return fmt.Sprintf("%#x", mark)
	}
	return fmt.Sprintf("%#x/%#x", mark, mask)
}

func canonicalPrefixes(raw []string) ([]string, error) {
	set := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		prefix, err := netip.ParsePrefix(item)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 prefix", item)
		}
		set[prefix.Masked().String()] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for prefix := range set {
		result = append(result, prefix)
	}
	sort.Strings(result)
	return result, nil
}

// RestoreInput atomically flushes/repopulates only the dedicated chains. The
// caller invokes `iptables-restore --noflush`; foreign chains and built-in
// policies are not represented in this transaction and remain untouched.
func (r Ruleset) RestoreInput() string {
	var b strings.Builder
	for _, chain := range r.Chains {
		fmt.Fprintf(&b, "*%s\n", chain.Table)
		fmt.Fprintf(&b, ":%s - [0:0]\n", chain.Name)
		fmt.Fprintf(&b, "-F %s\n", chain.Name)
		for _, rule := range chain.Rules {
			fmt.Fprintf(&b, "-A %s %s\n", chain.Name, rule)
		}
		b.WriteString("COMMIT\n")
	}
	return b.String()
}

func (r Ruleset) RuleCount() int {
	n := 0
	for _, chain := range r.Chains {
		n += len(chain.Rules)
	}
	return n
}

func (r Ruleset) Summary() []string {
	result := make([]string, 0, len(r.Chains))
	for _, chain := range r.Chains {
		result = append(result, fmt.Sprintf("%s/%s rules=%d jump=%s", chain.Table, chain.Name, len(chain.Rules), chain.Hook))
	}
	return result
}

func RuleIsOwned(rule string) bool {
	return strings.Contains(rule, "--comment "+OwnerComment) || strings.Contains(rule, "--comment \""+OwnerComment+"\"")
}
