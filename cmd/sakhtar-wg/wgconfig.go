package main

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wireGuardConfigurer interface {
	ConfigureDevice(string, wgtypes.Config) error
	Device(string) (*wgtypes.Device, error)
}

// wgConfig is pure compilation from validated configuration to wgctrl input.
// Keeping it separate from netlink effects makes it portable and deterministic.
func wgConfig(t Tunnel) (wgtypes.Config, error) {
	priv, err := wgtypes.ParseKey(t.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("%s: private_key: %w", t.Name, err)
	}
	pub, err := wgtypes.ParseKey(t.Peer.PublicKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("%s: peer.public_key: %w", t.Name, err)
	}
	endpoint, err := net.ResolveUDPAddr("udp", t.Peer.Endpoint)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("%s: peer.endpoint %q: %w", t.Name, t.Peer.Endpoint, err)
	}
	allowed := make([]net.IPNet, 0, len(t.Peer.AllowedIPs))
	for _, cidr := range t.Peer.AllowedIPs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("%s: allowed_ips %q: %w", t.Name, cidr, err)
		}
		allowed = append(allowed, *ipnet)
	}

	peer := wgtypes.PeerConfig{
		PublicKey:         pub,
		Endpoint:          endpoint,
		ReplaceAllowedIPs: true,
		AllowedIPs:        allowed,
	}
	if t.Peer.Keepalive > 0 {
		ka := time.Duration(t.Peer.Keepalive) * time.Second
		peer.PersistentKeepaliveInterval = &ka
	}
	return wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{peer},
	}, nil
}
