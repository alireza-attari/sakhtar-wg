//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	kernelstate "github.com/alireza-attari/sakhtar-wg/internal/kernel"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	mainTable       = 254
	linkAliasPrefix = "sakhtar-wg:v1:"
	linkModeCreated = "created"
	linkModeAdopted = "adopted"
)

// tunnelUp mutates only objects with explicit ownership evidence. wgctrl is
// intentionally called after the link type/alias/key identity has been proved.
func tunnelUp(wg wireGuardConfigurer, t Tunnel) error {
	cfg, err := wgConfig(t)
	if err != nil {
		return err
	}
	link, err := ensureOwnedLink(wg, t)
	if err != nil {
		return err
	}
	mode, err := ownedLinkMode(link, t)
	if err != nil {
		return err
	}
	if mode == linkModeAdopted {
		if err := verifyAdoptedLink(wg, link, t); err != nil {
			return err
		}
	}
	if link.Attrs().MTU != t.MTU {
		if err := netlink.LinkSetMTU(link, t.MTU); err != nil {
			return fmt.Errorf("%s: set MTU %d: %w", t.Name, t.MTU, err)
		}
	}
	if err := reconcileAddress(link, t); err != nil {
		return err
	}

	if mode != linkModeAdopted {
		if err := wg.ConfigureDevice(t.Name, cfg); err != nil {
			return fmt.Errorf("%s: configure wireguard: %w", t.Name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("%s: link up: %w", t.Name, err)
	}
	if err := requireSysctl("net/ipv4/conf/all/src_valid_mark", "1"); err != nil {
		return fmt.Errorf("%s: src_valid_mark: %w", t.Name, err)
	}
	if err := reconcileDefaultRoute(link, t); err != nil {
		return err
	}
	if err := reconcileRule(t); err != nil {
		return err
	}
	return reconcileRoutes(link, t)
}

func reconcileAddress(link netlink.Link, t Tunnel) error {
	desired, err := netlink.ParseAddr(t.Address)
	if err != nil {
		return fmt.Errorf("%s: address %q: %w", t.Name, t.Address, err)
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("%s: list addresses: %w", t.Name, err)
	}
	found := false
	for _, address := range addresses {
		if address.IPNet != nil && addressKey(address.IPNet) == addressKey(desired.IPNet) {
			found = true
			continue
		}
		if address.IPNet != nil && address.IPNet.IP.Equal(desired.IPNet.IP) {
			return fmt.Errorf("%s: address %s conflicts with desired %s; ownership is ambiguous", t.Name, address.IPNet, desired.IPNet)
		}
		if address.IPNet != nil {
			log.Printf("%s: preserving unattributed address %s as drift", t.Name, addressKey(address.IPNet))
		}
	}
	if found {
		return nil
	}
	if err := netlink.AddrAdd(link, desired); err != nil {
		return fmt.Errorf("%s: add address %s: %w", t.Name, desired, err)
	}
	return nil
}

func reconcileDefaultRoute(link netlink.Link, t Tunnel) error {
	dst := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	desired := netlink.Route{
		LinkIndex: link.Attrs().Index, Table: t.Table, Dst: dst,
		Protocol: netlink.RouteProtocol(kernelstate.RouteProtocol),
	}
	return reconcileRouteSet(t.Name, link, 0, []netlink.Route{desired}, func(route netlink.Route) bool {
		return route.Table != mainTable &&
			(int(route.Protocol) == kernelstate.RouteProtocol || route.Table == t.Table)
	})
}

// reconcileRoutes owns only main-table routes carrying the reserved protocol.
// Foreign routes on the same WireGuard interface remain byte-for-byte intact.
func reconcileRoutes(link netlink.Link, t Tunnel) error {
	desired := make([]netlink.Route, 0, len(t.Routes))
	for _, cidr := range t.Routes {
		_, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("%s: route %q: %w", t.Name, cidr, err)
		}
		desired = append(desired, netlink.Route{
			LinkIndex: link.Attrs().Index, Table: mainTable, Dst: prefix,
			Protocol: netlink.RouteProtocol(kernelstate.RouteProtocol),
		})
	}
	return reconcileRouteSet(t.Name, link, mainTable, desired, func(route netlink.Route) bool {
		return route.Table == mainTable
	})
}

func reconcileRouteSet(tunnelName string, link netlink.Link, table int, desired []netlink.Route, relevant func(netlink.Route) bool) error {
	existing, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: table}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("%s: list routes: %w", tunnelName, err)
	}
	var currentObjects []kernelstate.Object
	currentRoutes := map[string]netlink.Route{}
	for _, route := range existing {
		if !relevant(route) {
			continue
		}
		id := routeID(route)
		if _, duplicate := currentRoutes[id]; duplicate {
			return fmt.Errorf("%s: multiple routes occupy %s; refusing ambiguous reconciliation", tunnelName, id)
		}
		owned := int(route.Protocol) == kernelstate.RouteProtocol
		evidence := ""
		if owned {
			evidence = fmt.Sprintf("route protocol %d + owned link alias", kernelstate.RouteProtocol)
		}
		currentObjects = append(currentObjects, kernelstate.Object{
			Kind: kernelstate.Route, ID: id, Value: fmt.Sprintf("protocol=%d", route.Protocol),
			Owned: owned, Evidence: evidence,
		})
		currentRoutes[id] = route
	}
	desiredObjects := make([]kernelstate.Object, 0, len(desired))
	desiredRoutes := make(map[string]netlink.Route, len(desired))
	for _, route := range desired {
		id := routeID(route)
		desiredObjects = append(desiredObjects, kernelstate.Object{
			Kind: kernelstate.Route, ID: id, Value: fmt.Sprintf("protocol=%d", kernelstate.RouteProtocol),
			Owned: true, Evidence: fmt.Sprintf("route protocol %d + owned link alias", kernelstate.RouteProtocol),
		})
		desiredRoutes[id] = route
	}
	plan, err := kernelstate.PlanDiff(currentObjects, desiredObjects)
	if err != nil {
		return fmt.Errorf("%s: plan routes: %w", tunnelName, err)
	}
	if plan.HasBlockingDrift() {
		return fmt.Errorf("%s: route ownership conflict at %s: %s", tunnelName, plan.Drift[0].ID, plan.Drift[0].Reason)
	}
	// Additions precede withdrawals. A failed add therefore leaves the last-good
	// route set in place for the caller's deterministic repair pass.
	for _, phase := range []kernelstate.Action{kernelstate.Add, kernelstate.Delete} {
		for _, operation := range plan.Operations {
			if operation.Action != phase {
				continue
			}
			switch operation.Action {
			case kernelstate.Add:
				route := desiredRoutes[operation.ID]
				if err := netlink.RouteAdd(&route); err != nil {
					return fmt.Errorf("%s: add route %s: %w", tunnelName, operation.ID, err)
				}
			case kernelstate.Delete:
				route := currentRoutes[operation.ID]
				if err := netlink.RouteDel(&route); err != nil && !errors.Is(err, syscall.ENOENT) {
					return fmt.Errorf("%s: delete owned route %s: %w", tunnelName, operation.ID, err)
				}
			default:
				return fmt.Errorf("%s: unsupported route operation %s", tunnelName, operation.Action)
			}
		}
	}
	return nil
}

func routeID(route netlink.Route) string {
	return fmt.Sprintf("table=%d/link=%d/dst=%s", route.Table, route.LinkIndex, routeDestination(route))
}

func routeDestination(route netlink.Route) string {
	if route.Dst == nil {
		return "0.0.0.0/0"
	}
	return route.Dst.String()
}

func reconcileRule(t Tunnel) error {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("%s: list policy rules: %w", t.Name, err)
	}
	desired := markRule(t)
	var exact []netlink.Rule
	for _, rule := range rules {
		if rule.Priority != desired.Priority {
			continue
		}
		if ruleEqual(rule, *desired) {
			exact = append(exact, rule)
			continue
		}
		if int(rule.Protocol) != kernelstate.RouteProtocol {
			return fmt.Errorf("%s: rule priority %d is occupied by an unowned/conflicting rule", t.Name, t.RulePriority)
		}
		owned := rule
		if err := netlink.RuleDel(&owned); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("%s: replace owned rule priority %d: %w", t.Name, t.RulePriority, err)
		}
	}
	if len(exact) > 0 {
		for _, duplicate := range exact[1:] {
			copy := duplicate
			if err := netlink.RuleDel(&copy); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("%s: delete duplicate owned rule priority %d: %w", t.Name, t.RulePriority, err)
			}
		}
		return nil
	}
	if err := netlink.RuleAdd(desired); err != nil {
		return fmt.Errorf("%s: add policy rule priority %d mark %#x/%#x table %d: %w",
			t.Name, t.RulePriority, uint32(t.Fwmark), t.FwmarkMask, t.Table, err)
	}
	return nil
}

func markRule(t Tunnel) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = t.RulePriority
	rule.Mark = uint32(t.Fwmark)
	mask := t.FwmarkMask
	rule.Mask = &mask
	rule.Table = t.Table
	rule.Protocol = uint8(kernelstate.RouteProtocol)
	return rule
}

func ruleEqual(a, b netlink.Rule) bool {
	return a.Priority == b.Priority && a.Mark == b.Mark && ruleMask(a.Mask) == ruleMask(b.Mask) &&
		a.Table == b.Table && a.Protocol == b.Protocol
}

func ruleMask(mask *uint32) uint32 {
	if mask == nil {
		return kernelstate.FullMarkMask
	}
	return *mask
}

func applyRoutes(cfg *Config) {
	var applyErrors []error
	kernelDrift, firewallDrift := 0, 0
	if cfg.Gateway.Enabled {
		if _, err := compileGatewayRuleset(cfg); err != nil {
			log.Printf("routes: preflight gateway policy: %v", err)
			if statusErr := recordReconcileStatus(0, 1, err); statusErr != nil {
				log.Printf("routes: record reconcile status: %v", statusErr)
			}
			return
		}
	}
	for _, t := range cfg.Tunnels {
		link, found, err := lookupLink(t.Name)
		if err != nil {
			log.Printf("routes: %s: %v", t.Name, err)
			applyErrors = append(applyErrors, err)
			kernelDrift++
			continue
		}
		if !found {
			log.Printf("routes: %s: link not found", t.Name)
			applyErrors = append(applyErrors, fmt.Errorf("%s: link not found", t.Name))
			kernelDrift++
			continue
		}
		if _, err := ownedLinkMode(link, t); err != nil {
			log.Printf("routes: %s: %v", t.Name, err)
			applyErrors = append(applyErrors, err)
			kernelDrift++
			continue
		}
		if err := reconcileRoutes(link, t); err != nil {
			log.Printf("routes: %s: %v", t.Name, err)
			applyErrors = append(applyErrors, err)
			kernelDrift++
		}
	}
	if err := gatewayUp(cfg); err != nil {
		log.Printf("routes: gateway: %v", err)
		applyErrors = append(applyErrors, err)
		firewallDrift++
	}
	if err := recordReconcileStatus(kernelDrift, firewallDrift, errors.Join(applyErrors...)); err != nil {
		log.Printf("routes: record reconcile status: %v", err)
	}
}

// tunnelDown removes exact owned tuples. An owned-created link is deleted only
// when no unexpected address/route remains; an adopted link is never deleted.
func tunnelDown(t Tunnel) error {
	var cleanup []error
	if err := deleteOwnedRule(t); err != nil {
		cleanup = append(cleanup, err)
	}
	link, found, err := lookupLink(t.Name)
	if err != nil {
		cleanup = append(cleanup, err)
		return errors.Join(cleanup...)
	}
	if !found {
		return errors.Join(cleanup...)
	}
	mode, err := ownedLinkMode(link, t)
	if err != nil {
		cleanup = append(cleanup, err)
		return errors.Join(cleanup...)
	}
	if err := deleteOwnedRoutes(link, t); err != nil {
		cleanup = append(cleanup, err)
	}

	address, parseErr := netlink.ParseAddr(t.Address)
	if parseErr != nil {
		cleanup = append(cleanup, fmt.Errorf("%s: parse owned address: %w", t.Name, parseErr))
	}
	addresses, listAddrErr := netlink.AddrList(link, netlink.FAMILY_V4)
	if listAddrErr != nil {
		cleanup = append(cleanup, fmt.Errorf("%s: list addresses before delete: %w", t.Name, listAddrErr))
	}
	if mode == linkModeAdopted {
		if parseErr == nil && listAddrErr == nil && containsAddress(addresses, address) {
			if err := netlink.AddrDel(link, address); err != nil && !errors.Is(err, syscall.ENOENT) {
				cleanup = append(cleanup, fmt.Errorf("%s: delete owned address: %w", t.Name, err))
			}
		}
		if len(cleanup) == 0 {
			if err := netlink.LinkSetAlias(link, ""); err != nil {
				cleanup = append(cleanup, fmt.Errorf("%s: clear adoption marker: %w", t.Name, err))
			}
		}
		return errors.Join(cleanup...)
	}

	if listAddrErr == nil {
		for _, current := range addresses {
			if address == nil || current.IPNet == nil || addressKey(current.IPNet) != addressKey(address.IPNet) {
				cleanup = append(cleanup, fmt.Errorf("%s: foreign address %v prevents owned-link deletion", t.Name, current.IPNet))
			}
		}
	}
	remainingRoutes, routeErr := listAllRoutesOnLink(link, netlink.FAMILY_ALL)
	if routeErr != nil {
		cleanup = append(cleanup, fmt.Errorf("%s: list routes before link delete: %w", t.Name, routeErr))
	} else {
		foreignRoutes := 0
		for _, route := range remainingRoutes {
			if !addressGeneratedRoute(route, address) && !linkGeneratedRoute(route) {
				foreignRoutes++
			}
		}
		if foreignRoutes != 0 {
			cleanup = append(cleanup, fmt.Errorf("%s: %d foreign/unattributed route(s) prevent owned-link deletion", t.Name, foreignRoutes))
		}
	}
	if len(cleanup) == 0 {
		if err := netlink.LinkDel(link); err != nil && !errors.Is(err, syscall.ENOENT) {
			cleanup = append(cleanup, fmt.Errorf("%s: delete owned link: %w", t.Name, err))
		}
	}
	return errors.Join(cleanup...)
}

func deleteOwnedRule(t Tunnel) error {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("%s: list rules for cleanup: %w", t.Name, err)
	}
	desired := markRule(t)
	for _, rule := range rules {
		if ruleEqual(rule, *desired) {
			copy := rule
			if err := netlink.RuleDel(&copy); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("%s: delete owned rule: %w", t.Name, err)
			}
		}
	}
	return nil
}

func deleteExactOwnedAddress(t Tunnel) error {
	link, found, err := lookupLink(t.Name)
	if err != nil || !found {
		return err
	}
	if _, err := ownedLinkMode(link, t); err != nil {
		return err
	}
	desired, err := netlink.ParseAddr(t.Address)
	if err != nil {
		return fmt.Errorf("%s: parse address for exact cleanup: %w", t.Name, err)
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("%s: list addresses for exact cleanup: %w", t.Name, err)
	}
	if containsAddress(addresses, desired) {
		if err := netlink.AddrDel(link, desired); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("%s: delete exact owned address %s: %w", t.Name, addressKey(desired.IPNet), err)
		}
	}
	return nil
}

func deleteOwnedRoutes(link netlink.Link, t Tunnel) error {
	routes, err := listAllRoutesOnLink(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("%s: list routes for cleanup: %w", t.Name, err)
	}
	var cleanup []error
	for _, route := range routes {
		if int(route.Protocol) != kernelstate.RouteProtocol {
			continue
		}
		copy := route
		if err := netlink.RouteDel(&copy); err != nil && !errors.Is(err, syscall.ENOENT) {
			cleanup = append(cleanup, fmt.Errorf("%s: delete owned route %s: %w", t.Name, routeID(route), err))
		}
	}
	return errors.Join(cleanup...)
}

func deleteOwnedDefaultRoute(t Tunnel) error {
	link, found, err := lookupLink(t.Name)
	if err != nil || !found {
		return err
	}
	if _, err := ownedLinkMode(link, t); err != nil {
		return err
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: t.Table},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("%s: list owned default route in table %d: %w", t.Name, t.Table, err)
	}
	var cleanup []error
	for _, route := range routes {
		if int(route.Protocol) != kernelstate.RouteProtocol || routeDestination(route) != "0.0.0.0/0" {
			continue
		}
		copy := route
		if err := netlink.RouteDel(&copy); err != nil && !errors.Is(err, syscall.ENOENT) {
			cleanup = append(cleanup, fmt.Errorf("%s: delete owned default route in table %d: %w", t.Name, t.Table, err))
		}
	}
	return errors.Join(cleanup...)
}

func listAllRoutesOnLink(link netlink.Link, family int) ([]netlink.Route, error) {
	// Setting RT_FILTER_TABLE with RT_TABLE_UNSPEC asks netlink for every table;
	// without it vishvananda/netlink intentionally returns main-table routes only.
	return netlink.RouteListFiltered(family,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: 0},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
}

func containsAddress(addresses []netlink.Addr, desired *netlink.Addr) bool {
	if desired == nil || desired.IPNet == nil {
		return false
	}
	for _, address := range addresses {
		if address.IPNet != nil && addressKey(address.IPNet) == addressKey(desired.IPNet) {
			return true
		}
	}
	return false
}

func addressKey(address *net.IPNet) string {
	if address == nil {
		return ""
	}
	ones, _ := address.Mask.Size()
	return fmt.Sprintf("%s/%d", address.IP.String(), ones)
}

// Linux synthesizes proto-kernel connected/local/broadcast routes from an
// address. They share the address's lifetime and are safe to remove with the
// owned-created link; every other remaining route blocks link deletion.
func addressGeneratedRoute(route netlink.Route, address *netlink.Addr) bool {
	if address == nil || address.IPNet == nil || route.Dst == nil || int(route.Protocol) != 2 {
		return false
	}
	if route.Src != nil && route.Src.Equal(address.IPNet.IP) {
		return true
	}
	return route.Dst.String() == address.IPNet.String() || route.Dst.IP.Equal(address.IPNet.IP)
}

func linkGeneratedRoute(route netlink.Route) bool {
	return int(route.Protocol) == 2 && route.Table == 255 && route.Dst != nil && route.Dst.String() == "ff00::/8"
}

func ensureOwnedLink(wg wireGuardConfigurer, t Tunnel) (netlink.Link, error) {
	link, found, err := lookupLink(t.Name)
	if err != nil {
		return nil, err
	}
	if !found {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = t.Name
		attrs.MTU = t.MTU
		candidate := &netlink.GenericLink{LinkAttrs: attrs, LinkType: "wireguard"}
		if err := netlink.LinkAdd(candidate); err != nil {
			return nil, fmt.Errorf("%s: create wireguard link: %w", t.Name, err)
		}
		created, found, lookupErr := lookupLink(t.Name)
		if lookupErr != nil || !found {
			if lookupErr == nil {
				lookupErr = fmt.Errorf("link disappeared after creation")
			}
			deleteErr := netlink.LinkDel(candidate)
			return nil, errors.Join(fmt.Errorf("%s: look up newly-created link: %w", t.Name, lookupErr), deleteErr)
		}
		if err := netlink.LinkSetAlias(created, ownershipAlias(t, linkModeCreated)); err != nil {
			deleteErr := netlink.LinkDel(created)
			return nil, errors.Join(fmt.Errorf("%s: set ownership alias: %w", t.Name, err), deleteErr)
		}
		marked, found, err := lookupLink(t.Name)
		if err != nil || !found {
			if err == nil {
				err = fmt.Errorf("link disappeared after alias update")
			}
			deleteErr := netlink.LinkDel(created)
			return nil, errors.Join(fmt.Errorf("%s: verify ownership alias: %w", t.Name, err), deleteErr)
		}
		return marked, nil
	}

	if link.Type() != "wireguard" {
		return nil, fmt.Errorf("%s: existing link is %q, not wireguard", t.Name, link.Type())
	}
	if _, err := ownedLinkMode(link, t); err == nil {
		if err := verifyExistingKeyIdentity(wg, t); err != nil {
			return nil, err
		}
		return link, nil
	}
	if !t.AdoptExisting {
		return nil, fmt.Errorf("%s: same-name link exists without the expected sakhtar-wg ownership marker", t.Name)
	}
	if link.Attrs().Alias != "" {
		return nil, fmt.Errorf("%s: existing link alias %q is foreign; refusing to overwrite metadata", t.Name, link.Attrs().Alias)
	}
	if err := verifyAdoptionCandidate(wg, link, t); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetAlias(link, ownershipAlias(t, linkModeAdopted)); err != nil {
		return nil, fmt.Errorf("%s: mark adopted link: %w", t.Name, err)
	}
	marked, found, err := lookupLink(t.Name)
	if err != nil || !found {
		if err == nil {
			err = fmt.Errorf("link disappeared after adoption")
		}
		return nil, fmt.Errorf("%s: verify adoption marker: %w", t.Name, err)
	}
	return marked, nil
}

func lookupLink(name string) (netlink.Link, bool, error) {
	link, err := netlink.LinkByName(name)
	if err == nil {
		return link, true, nil
	}
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("%s: lookup link: %w", name, err)
}

func ownedLinkMode(link netlink.Link, t Tunnel) (string, error) {
	for _, mode := range []string{linkModeCreated, linkModeAdopted} {
		if link.Attrs().Alias == ownershipAlias(t, mode) {
			return mode, nil
		}
	}
	return "", fmt.Errorf("%s: ownership alias %q does not match configured key identity", t.Name, link.Attrs().Alias)
}

func ownershipAlias(t Tunnel, mode string) string {
	key, err := wgtypes.ParseKey(t.PrivateKey)
	if err != nil {
		return linkAliasPrefix + mode + ":invalid"
	}
	publicKey := key.PublicKey()
	digest := sha256.Sum256(publicKey[:])
	return linkAliasPrefix + mode + ":" + hex.EncodeToString(digest[:8])
}

func verifyExistingKeyIdentity(wg wireGuardConfigurer, t Tunnel) error {
	device, err := wg.Device(t.Name)
	if err != nil {
		return fmt.Errorf("%s: inspect wireguard identity: %w", t.Name, err)
	}
	privateKey, err := wgtypes.ParseKey(t.PrivateKey)
	if err != nil {
		return fmt.Errorf("%s: parse private key for identity: %w", t.Name, err)
	}
	if device.PublicKey != (wgtypes.Key{}) && device.PublicKey != privateKey.PublicKey() {
		return fmt.Errorf("%s: owned link has an unexpected WireGuard key identity", t.Name)
	}
	return nil
}

func verifyAdoptionCandidate(wg wireGuardConfigurer, link netlink.Link, t Tunnel) error {
	if link.Attrs().MTU != t.MTU {
		return fmt.Errorf("%s: adoption refused: MTU %d differs from desired %d", t.Name, link.Attrs().MTU, t.MTU)
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return fmt.Errorf("%s: adoption refused: existing link must already be up", t.Name)
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("%s: inspect addresses before adoption: %w", t.Name, err)
	}
	if len(addresses) != 0 {
		return fmt.Errorf("%s: adoption refused: existing link has %d address(es)", t.Name, len(addresses))
	}
	routes, err := listAllRoutesOnLink(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("%s: inspect routes before adoption: %w", t.Name, err)
	}
	conflictingRoutes := 0
	for _, route := range routes {
		if !linkGeneratedRoute(route) {
			conflictingRoutes++
		}
	}
	if conflictingRoutes != 0 {
		return fmt.Errorf("%s: adoption refused: existing link has %d conflicting route(s)", t.Name, conflictingRoutes)
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("%s: inspect rules before adoption: %w", t.Name, err)
	}
	for _, rule := range rules {
		if rule.Priority == t.RulePriority || rule.Mark == uint32(t.Fwmark) || rule.Table == t.Table {
			return fmt.Errorf("%s: adoption refused: conflicting policy rule at priority %d", t.Name, rule.Priority)
		}
	}
	device, err := wg.Device(t.Name)
	if err != nil {
		return fmt.Errorf("%s: inspect WireGuard config before adoption: %w", t.Name, err)
	}
	matches, err := deviceMatchesTunnel(device, t)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("%s: adoption refused: WireGuard key/peer configuration differs from desired state", t.Name)
	}
	return nil
}

func verifyAdoptedLink(wg wireGuardConfigurer, link netlink.Link, t Tunnel) error {
	if link.Attrs().MTU != t.MTU || link.Attrs().Flags&net.FlagUp == 0 {
		return fmt.Errorf("%s: adopted link MTU/up state drifted; refusing to mutate pre-existing link properties", t.Name)
	}
	device, err := wg.Device(t.Name)
	if err != nil {
		return fmt.Errorf("%s: inspect adopted WireGuard config: %w", t.Name, err)
	}
	matches, err := deviceMatchesTunnel(device, t)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("%s: adopted WireGuard configuration drifted; refusing to overwrite pre-existing device state", t.Name)
	}
	return nil
}

func deviceMatchesTunnel(device *wgtypes.Device, t Tunnel) (bool, error) {
	compiled, err := wgConfig(t)
	if err != nil {
		return false, err
	}
	if compiled.PrivateKey == nil || device.PublicKey != compiled.PrivateKey.PublicKey() || len(device.Peers) != 1 || len(compiled.Peers) != 1 {
		return false, nil
	}
	current, desired := device.Peers[0], compiled.Peers[0]
	if current.PublicKey != desired.PublicKey || current.PersistentKeepaliveInterval != derefDuration(desired.PersistentKeepaliveInterval) {
		return false, nil
	}
	if (current.Endpoint == nil) != (desired.Endpoint == nil) || current.Endpoint != nil && current.Endpoint.String() != desired.Endpoint.String() {
		return false, nil
	}
	currentAllowed := make([]string, 0, len(current.AllowedIPs))
	desiredAllowed := make([]string, 0, len(desired.AllowedIPs))
	for _, prefix := range current.AllowedIPs {
		currentAllowed = append(currentAllowed, prefix.String())
	}
	for _, prefix := range desired.AllowedIPs {
		desiredAllowed = append(desiredAllowed, prefix.String())
	}
	sort.Strings(currentAllowed)
	sort.Strings(desiredAllowed)
	return strings.Join(currentAllowed, ",") == strings.Join(desiredAllowed, ","), nil
}

func derefDuration(value *time.Duration) time.Duration {
	if value == nil {
		return 0
	}
	return *value
}

// validateKernelReservations fails before mutation when another component uses
// sakhtar-wg's route protocol or policy-rule priority allocation.
func validateKernelReservations(cfg *Config) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links for ownership validation: %w", err)
	}
	ownedIndices := map[int]bool{}
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Alias, linkAliasPrefix) {
			ownedIndices[link.Attrs().Index] = true
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: 0, Protocol: netlink.RouteProtocol(kernelstate.RouteProtocol)},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return fmt.Errorf("list reserved-protocol routes: %w", err)
	}
	for _, route := range routes {
		if !ownedIndices[route.LinkIndex] {
			return fmt.Errorf("route protocol %d conflict at %s: output link lacks sakhtar-wg ownership", kernelstate.RouteProtocol, routeID(route))
		}
	}

	desired := make(map[int]netlink.Rule, len(cfg.Tunnels))
	for _, tunnel := range cfg.Tunnels {
		desired[tunnel.RulePriority] = *markRule(tunnel)
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list rules for ownership validation: %w", err)
	}
	for _, rule := range rules {
		inRange := rule.Priority >= kernelstate.RulePriorityMin && rule.Priority <= kernelstate.RulePriorityMax
		if !inRange && int(rule.Protocol) != kernelstate.RouteProtocol {
			continue
		}
		expected, ok := desired[rule.Priority]
		if !ok || !ruleEqual(rule, expected) {
			return fmt.Errorf("policy-rule ownership conflict at reserved priority %d", rule.Priority)
		}
	}
	return nil
}

type sysctlRecord struct {
	Required string
	Previous string
}

var requiredSysctls = struct {
	sync.Mutex
	values map[string]sysctlRecord
}{values: map[string]sysctlRecord{}}

// requireSysctl records the previous value before changing it. Global sysctls
// are intentionally not restored: exclusive ownership cannot be proved.
func requireSysctl(key, value string) error {
	path := "/proc/sys/" + key
	currentBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	current := strings.TrimSpace(string(currentBytes))
	requiredSysctls.Lock()
	if _, recorded := requiredSysctls.values[key]; !recorded {
		requiredSysctls.values[key] = sysctlRecord{Required: value, Previous: current}
	}
	requiredSysctls.Unlock()
	if current == value {
		return nil
	}
	return os.WriteFile(path, []byte(value), 0o644)
}

// writeSysctl remains the single gateway/tunnel entry point while preserving
// previous-state reporting and the default no-restore policy.
func writeSysctl(key, value string) error { return requireSysctl(key, value) }
