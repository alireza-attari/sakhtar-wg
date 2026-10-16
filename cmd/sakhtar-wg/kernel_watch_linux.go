//go:build linux

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/alireza-attari/sakhtar-wg/internal/observability"
)

// kernelReconcileInterval bounds how long the box can egress through the wrong
// path after something outside the daemon removes an object it owns.
//
// Reload already repairs plumbing (since 2026-08-09), but nothing ran it on its
// own: on 2026-10-15 an unattended upgrade restarted systemd-networkd, which
// flushes foreign policy rules by default, and every SNI bypass domain left via
// the plain WAN for 40 hours until someone ran `systemctl reload`. Neither the
// handshake monitor nor the active probe could notice: probes dial with the
// tunnel's SO_MARK, and a marked packet with no rule still routes via main and
// still succeeds. Only diffing the kernel against the config sees it.
const kernelReconcileInterval = 30 * time.Second

// repair measures the live kernel and firewall against cfg and reapplies the
// owned state when they disagree. It runs on the main loop goroutine, like
// every other kernel mutation, so it never races a reload or a route refresh.
func (w *kernelWatch) repair(wg wireGuardConfigurer, cfg *Config, registry *observability.Registry) {
	changes, blocking, err := pendingChanges(wg, cfg)
	if err != nil {
		if w.observe([]string{"measure: " + err.Error()}) {
			slog.Warn("kernel.measure_failed", "component", "kernel", "outcome", "failure", "error", err)
		}
		return
	}
	if len(changes) == 0 {
		if w.observe(nil) {
			slog.Info("kernel.in_sync", "component", "kernel", "outcome", "ok")
		}
		if status, err := readReconcileStatus(); err == nil && (status.KernelDriftGauge != 0 || status.FirewallDriftGauge != 0) {
			measureAndRecordDrift(wg, cfg, nil)
		}
		return
	}
	if blocking {
		// Startup refuses to mutate over blocking drift; so does the watchdog.
		if w.observe(changes) {
			slog.Error("kernel.repair_refused", "component", "kernel", "outcome", "failure",
				"reason", "blocking drift", "changes", strings.Join(changes, "; "))
		}
		measureAndRecordDrift(wg, cfg, errors.New("blocking kernel drift; repair refused"))
		return
	}

	repairErr := reapplyOwnedState(wg, cfg)
	remaining, _, measureErr := pendingChanges(wg, cfg)
	measureAndRecordDrift(wg, cfg, repairErr)
	if repairErr == nil && measureErr == nil && len(remaining) == 0 {
		registry.RecordKernelRepair("success")
		w.observe(nil)
		slog.Warn("kernel.repaired", "component", "kernel", "outcome", "success", "changes", strings.Join(changes, "; "))
		return
	}
	registry.RecordKernelRepair("failure")
	if w.observe(remaining) {
		slog.Error("kernel.repair_failed", "component", "kernel", "outcome", "failure",
			"changes", strings.Join(changes, "; "), "remaining", strings.Join(remaining, "; "),
			"error", errors.Join(repairErr, measureErr))
	}
}

func pendingChanges(wg wireGuardConfigurer, cfg *Config) (changes []string, blocking bool, err error) {
	plan, err := buildKernelPlan(wg, cfg)
	if err != nil {
		return nil, false, err
	}
	changes = kernelChanges(plan)
	firewall, err := buildFirewallPlan(cfg)
	if err != nil {
		return nil, false, err
	}
	if len(firewall) > 0 {
		changes = append(changes, fmt.Sprintf("firewall %d changes", len(firewall)))
	}
	return changes, plan.HasBlockingDrift(), nil
}

// reapplyOwnedState mirrors applyReload's unchanged-tunnel path: a missing link
// is brought back up, otherwise only the plumbing around the device is touched
// so a live tunnel is not re-handshaken.
func reapplyOwnedState(wg wireGuardConfigurer, cfg *Config) error {
	var errs []error
	for _, t := range cfg.Tunnels {
		link, found, err := lookupLink(t.Name)
		switch {
		case err != nil:
		case !found:
			err = tunnelUp(wg, t)
		default:
			err = reconcilePlumbing(link, t)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := gatewayUp(cfg); err != nil {
		errs = append(errs, fmt.Errorf("gateway: %w", err))
	}
	return errors.Join(errs...)
}
