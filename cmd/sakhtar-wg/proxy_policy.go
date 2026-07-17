package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var defaultDeniedDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation (TEST-NET-1)
	netip.MustParsePrefix("198.51.100.0/24"), // documentation (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation (TEST-NET-3)
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("2001:2::/48"),     // benchmarking
}

// canonicalHost is the single normalization boundary for SNI, HTTP Host, and
// configured suffixes. Unicode input is deliberately rejected; callers may use
// valid lower-case ASCII A-labels (punycode). One trailing root dot is accepted
// and removed. A syntactically valid HTTP port is accepted only when allowPort
// is true and is always stripped before routing or policy evaluation.
func canonicalHost(raw string, allowPort bool) (host string, isIP bool, err error) {
	if raw == "" || strings.TrimSpace(raw) != raw || !utf8.ValidString(raw) {
		return "", false, fmt.Errorf("host is empty or contains surrounding whitespace")
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e {
			return "", false, fmt.Errorf("unicode and control characters are not allowed")
		}
	}

	host = raw
	if allowPort {
		switch {
		case strings.HasPrefix(raw, "["):
			if strings.HasSuffix(raw, "]") {
				host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
			} else {
				var port string
				host, port, err = net.SplitHostPort(raw)
				if err != nil || !validPort(port) {
					return "", false, fmt.Errorf("host has an invalid port")
				}
			}
		case strings.Count(raw, ":") == 1:
			var port string
			host, port, err = net.SplitHostPort(raw)
			if err != nil || !validPort(port) {
				return "", false, fmt.Errorf("host has an invalid port")
			}
		case strings.Count(raw, ":") > 1:
			return "", false, fmt.Errorf("IPv6 HTTP Host literals must be bracketed")
		}
	} else if strings.HasPrefix(raw, "[") || strings.HasSuffix(raw, "]") {
		return "", false, fmt.Errorf("brackets are not allowed")
	}

	if host == "" || strings.Contains(host, "%") {
		return "", false, fmt.Errorf("host is empty or contains an IPv6 zone")
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		return ip.Unmap().String(), true, nil
	}
	if strings.Contains(host, ":") {
		return "", false, fmt.Errorf("host is neither a valid hostname nor IP literal")
	}
	if strings.HasSuffix(host, "..") {
		return "", false, fmt.Errorf("host has multiple trailing dots")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", false, fmt.Errorf("hostname length must be between 1 and 253 bytes")
	}
	ascii, idnaErr := idna.Lookup.ToASCII(host)
	if idnaErr != nil || ascii != host {
		return "", false, fmt.Errorf("hostname is not a valid ASCII IDNA name")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", false, fmt.Errorf("hostname contains an empty or oversized label")
		}
		if !isAlphaNum(label[0]) || !isAlphaNum(label[len(label)-1]) {
			return "", false, fmt.Errorf("hostname labels must start and end with a letter or digit")
		}
		for i := 1; i < len(label)-1; i++ {
			if !isAlphaNum(label[i]) && label[i] != '-' {
				return "", false, fmt.Errorf("hostname labels may contain only letters, digits, and hyphens")
			}
		}
	}
	if ambiguousIPName(labels) {
		return "", false, fmt.Errorf("ambiguous numeric IP-like hostname is not allowed")
	}
	return host, false, nil
}

func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

func isAlphaNum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func ambiguousIPName(labels []string) bool {
	last := labels[len(labels)-1]
	allDigits := true
	for i := range last {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return true
	}
	if len(labels) == 1 && len(last) > 2 && strings.HasPrefix(last, "0x") {
		for i := 2; i < len(last); i++ {
			if !strings.ContainsRune("0123456789abcdef", rune(last[i])) {
				return false
			}
		}
		return true
	}
	return false
}

func parsePolicyPrefix(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr := p.Addr()
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("zones are not allowed")
	}
	if addr.Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefixes broader than /96 are ambiguous")
		}
		p = netip.PrefixFrom(addr.Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

type destinationPolicy struct {
	allowByMark map[int][]netip.Prefix
}

func newDestinationPolicy(c *Config) destinationPolicy {
	p := destinationPolicy{allowByMark: map[int][]netip.Prefix{}}
	p.allowByMark[0] = mustPolicyPrefixes(c.Proxy.DestinationPolicy.DirectAllowCIDRs)
	for _, tunnel := range c.Tunnels {
		p.allowByMark[tunnel.Fwmark] = mustPolicyPrefixes(c.Proxy.DestinationPolicy.TunnelAllowCIDRs[tunnel.Name])
	}
	return p
}

func mustPolicyPrefixes(raw []string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefix, err := parsePolicyPrefix(value)
		if err == nil { // strict config validation has already reported errors
			result = append(result, prefix)
		}
	}
	return result
}

func (p destinationPolicy) requestedHostAllowed(host string, isIP bool, mark int, self map[netip.Addr]struct{}) bool {
	if isIP {
		addr, err := netip.ParseAddr(host)
		return err == nil && p.addressAllowed(addr, mark, self)
	}
	return host != "localhost" && host != "localhost.localdomain" && host != "ip6-localhost" &&
		host != "ip6-loopback" && host != "broadcasthost" &&
		!strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".local")
}

func (p destinationPolicy) addressAllowed(addr netip.Addr, mark int, self map[netip.Addr]struct{}) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	if _, found := self[addr]; found {
		return false
	}
	denied := addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
	for _, prefix := range defaultDeniedDestinationPrefixes {
		if prefix.Contains(addr) {
			denied = true
			break
		}
	}
	if !denied {
		return true
	}
	for _, prefix := range p.allowByMark[mark] {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func compileSourceACL(c *Config) []netip.Prefix {
	if len(c.Proxy.AllowedSourceCIDRs) == 0 {
		return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	}
	return mustPolicyPrefixes(c.Proxy.AllowedSourceCIDRs)
}

func sourceAllowed(addr net.Addr, prefixes []netip.Prefix) (netip.Addr, bool) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return ip, true
		}
	}
	return ip, false
}
