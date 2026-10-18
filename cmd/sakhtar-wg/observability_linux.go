//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	internalhealth "github.com/alireza-attari/sakhtar-wg/internal/health"
	"github.com/alireza-attari/sakhtar-wg/internal/observability"
)

func healthObserver(registry *observability.Registry, activeProbe bool) func(internalhealth.Snapshot) {
	return func(snapshot internalhealth.Snapshot) {
		items := make([]observability.WGSnapshot, 0, len(snapshot.Tunnels))
		failed := false
		for _, tunnel := range snapshot.Tunnels {
			items = append(items, observability.WGSnapshot{
				Tunnel: string(tunnel.Tunnel), Signal: string(tunnel.Signal), HandshakeAge: tunnel.HandshakeAgeSec,
				ReceiveBytes: tunnel.ReceiveBytes, TransmitBytes: tunnel.TransmitBytes,
			})
			failed = failed || tunnel.Signal == internalhealth.SessionFailed
		}
		registry.SetWG(items)
		groups := make([]observability.GroupSnapshot, 0, len(snapshot.Groups))
		for _, group := range snapshot.Groups {
			groups = append(groups, observability.GroupSnapshot{Name: group.Name, State: group.State, Reason: group.Reason, ActiveMark: uint32(group.ActiveMark)})
		}
		registry.SetGroups(groups)
		outcome := "ok"
		if failed {
			outcome = "degraded"
		}
		// Passive WireGuard evidence informs failover and status, but does not gate
		// process readiness: an idle peer can legitimately have an old handshake.
		if !activeProbe {
			registry.SetComponent("health", false, !failed, outcome, nil)
		}
	}
}

// startActiveProbe runs one active reachability probe per tunnel (or only the
// named one, when health_probe.via is set) and publishes each result under that
// tunnel's name.
//
// Per tunnel is the whole point. WireGuard reports a fresh handshake for a
// tunnel whose exit has stopped resolving DNS or is dropping most of its
// packets, and an aggregate probe through a single tunnel says nothing about
// its peers — so a degraded member can sit in a group looking healthy while
// every connection that lands on it fails.
func startActiveProbe(ctx context.Context, config *Config, registry *observability.Registry) []*internalhealth.Prober {
	if config == nil || !config.HealthProbe.Enabled {
		return nil
	}
	targets := make([]string, 0, len(config.Tunnels))
	if config.HealthProbe.Via != "" {
		targets = append(targets, config.HealthProbe.Via)
	} else {
		for _, tunnel := range config.Tunnels {
			targets = append(targets, tunnel.Name)
		}
	}

	// The component verdict is an OR across tunnels: one reachable egress still
	// means the daemon can serve, so a single degraded member must not report the
	// whole health component down. Its own per-tunnel metric carries that detail.
	var mu sync.Mutex
	lastByTunnel := make(map[string]bool, len(targets))

	probers := make([]*internalhealth.Prober, 0, len(targets))
	for _, target := range targets {
		client := probeHTTPClient(config, target)
		prober := internalhealth.NewProber(internalhealth.ProbeConfig{
			Interval:      time.Duration(config.HealthProbe.Interval) * time.Second,
			Timeout:       time.Duration(config.HealthProbe.Timeout) * time.Second,
			Jitter:        float64(config.HealthProbe.JitterPercent) / 100,
			MaxConcurrent: config.HealthProbe.MaxConcurrent,
			Observe: func(result internalhealth.ProbeResult) {
				lastError := ""
				if result.Err != nil {
					lastError = result.Err.Error()
				}
				registry.SetProbe(observability.ProbeSnapshot{Tunnel: target, ObservedAt: result.At, Success: result.Success, DurationSecond: result.Duration.Seconds(), LastError: lastError})
				mu.Lock()
				lastByTunnel[target] = result.Success
				any := false
				for _, ok := range lastByTunnel {
					any = any || ok
				}
				mu.Unlock()
				registry.SetComponent("health", false, any, boolOutcome(any), result.Err)
			},
		}, func(probeCtx context.Context) error {
			request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, config.HealthProbe.Endpoint, nil)
			if err != nil {
				return err
			}
			response, err := client.Do(request)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
			_ = response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 400 {
				return fmt.Errorf("probe HTTP status class %dxx", response.StatusCode/100)
			}
			return nil
		})
		go prober.Run(ctx)
		probers = append(probers, prober)
	}
	return probers
}

func collectOperationalState(registry *observability.Registry, server *Server) {
	server.Observe(registry)
	registry.SetActiveGeneration(server.Generation())
	listenersReady := server.ListenersReady()
	registry.SetComponent("listeners", true, listenersReady, boolOutcome(listenersReady), nil)
	registry.SetComponent("proxy", true, listenersReady, boolOutcome(listenersReady), nil)
	registry.SetComponent("dns", false, true, "ok", nil)
	status, err := readReconcileStatus()
	if err != nil {
		registry.SetComponent("kernel", true, false, "failure", err)
		registry.SetComponent("firewall", true, false, "failure", err)
		return
	}
	registry.SetDrift(status.KernelDriftGauge, status.FirewallDriftGauge)
	var applyErr error
	if !status.LastApplySuccess {
		applyErr = errors.New(status.LastApplyError)
	}
	kernelReady := status.LastApplySuccess && status.KernelDriftGauge == 0
	firewallReady := status.LastApplySuccess && status.FirewallDriftGauge == 0
	registry.SetComponent("kernel", true, kernelReady, boolOutcome(kernelReady), applyErr)
	registry.SetComponent("firewall", true, firewallReady, boolOutcome(firewallReady), applyErr)
}

func boolOutcome(ok bool) string {
	if ok {
		return "ok"
	}
	return "failure"
}

func managementConfig(config Management) observability.ManagementConfig {
	return observability.ManagementConfig{
		Listen:            config.Listen,
		ReadHeaderTimeout: time.Duration(config.ReadHeaderTimeout) * time.Second,
		WriteTimeout:      time.Duration(config.WriteTimeout) * time.Second,
		IdleTimeout:       time.Duration(config.IdleTimeout) * time.Second,
		ShutdownTimeout:   time.Duration(config.ShutdownTimeout) * time.Second,
		MaxHeaderBytes:    config.MaxHeaderBytes,
		Pprof:             config.Pprof,
	}
}

func recordReload(registry *observability.Registry, server *Server, started time.Time, err error) {
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	registry.RecordReload(outcome, time.Since(started))
	// A rejected candidate does not make the already-active generation unready;
	// its failure remains visible as the component's last outcome/error.
	registry.SetComponent("config", true, true, outcome, err)
	args := []any{"component", "runtime", "generation", server.Generation(), "outcome", outcome, "duration", time.Since(started)}
	if err != nil {
		args = append(args, "error", err)
		slog.Error("config.reload_completed", args...)
		return
	}
	slog.Info("config.reload_completed", args...)
}
