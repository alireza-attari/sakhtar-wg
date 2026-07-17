package main

import (
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// printStatus prints a short per-tunnel view: endpoint, last handshake age and
// bytes transferred, read live from the kernel via wgctrl.
func printStatus(wg *wgctrl.Client, cfg *Config) {
	for _, t := range cfg.Tunnels {
		dev, err := wg.Device(t.Name)
		if err != nil {
			fmt.Printf("%-8s  down (%v)\n", t.Name, err)
			continue
		}
		fmt.Printf("%-8s  fwmark=%d table=%d\n", dev.Name, t.Fwmark, t.Table)
		if len(dev.Peers) == 0 {
			fmt.Printf("            no peer configured\n")
			continue
		}
		p := dev.Peers[0]
		hs := "never"
		if !p.LastHandshakeTime.IsZero() {
			hs = time.Since(p.LastHandshakeTime).Round(time.Second).String() + " ago"
		}
		fmt.Printf("            endpoint=%v handshake=%s rx=%s tx=%s\n",
			p.Endpoint, hs, humanBytes(p.ReceiveBytes), humanBytes(p.TransmitBytes))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
