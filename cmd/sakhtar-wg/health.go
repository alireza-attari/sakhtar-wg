package main

import (
	"context"
	"log/slog"
	"time"

	internalhealth "github.com/alireza-attari/sakhtar-wg/internal/health"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// HealthMonitor is owned by internal/health; this alias keeps composition and
// proxy routing concise while the remaining root package is extracted in later
// behavior-covered changes.
type HealthMonitor = internalhealth.Monitor

func NewHealthMonitor(c *Config, observers ...func(internalhealth.Snapshot)) (*HealthMonitor, error) {
	if len(c.Groups) == 0 {
		return nil, nil
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	config := internalhealth.Config{Interval: time.Duration(c.HealthInterval) * time.Second}
	if len(observers) > 0 {
		config.Observe = observers[0]
	}
	for _, group := range c.Groups {
		converted := internalhealth.Group{Name: group.Name, HealthyAfter: time.Duration(group.HealthyAfter) * time.Second}
		for _, member := range group.Members {
			converted.Members = append(converted.Members, internalhealth.Member{Tunnel: internalhealth.TunnelName(member), Mark: internalhealth.FwMark(c.markFor(member))})
		}
		config.Groups = append(config.Groups, converted)
	}
	monitor, err := internalhealth.New(client, config, slog.Default())
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return monitor, nil
}

func runHealthMonitor(ctx context.Context, monitor *HealthMonitor) <-chan struct{} {
	done := make(chan struct{})
	go func() { defer close(done); monitor.Run(ctx) }()
	return done
}
