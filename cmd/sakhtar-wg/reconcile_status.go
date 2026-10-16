//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"time"
)

const reconcileStatusFile = runtimeDir + "/reconcile.json"

type recordedSysctl struct {
	Required      string `json:"required"`
	Previous      string `json:"previous"`
	RestoreOnExit bool   `json:"restore_on_exit"`
}

type reconcileStatus struct {
	LastApplyTime      time.Time                 `json:"last_apply_time"`
	LastApplySuccess   bool                      `json:"last_apply_success"`
	LastApplyError     string                    `json:"last_apply_error,omitempty"`
	KernelDriftGauge   int                       `json:"kernel_drift"`
	FirewallDriftGauge int                       `json:"firewall_drift"`
	Sysctls            map[string]recordedSysctl `json:"sysctls"`
}

func recordReconcileStatus(kernelDrift, firewallDrift int, applyErr error) error {
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return err
	}
	status := reconcileStatus{
		LastApplyTime: time.Now().UTC(), LastApplySuccess: applyErr == nil,
		KernelDriftGauge: kernelDrift, FirewallDriftGauge: firewallDrift,
		Sysctls: map[string]recordedSysctl{},
	}
	// A standalone `down` process did not observe the pre-apply sysctl values.
	// Preserve the last recorded evidence rather than replacing it with unknown.
	if raw, readErr := os.ReadFile(reconcileStatusFile); readErr == nil {
		var previous reconcileStatus
		if json.Unmarshal(raw, &previous) == nil {
			for key, value := range previous.Sysctls {
				status.Sysctls[key] = value
			}
		}
	}
	if applyErr != nil {
		status.LastApplyError = applyErr.Error()
	}
	requiredSysctls.Lock()
	for key, value := range requiredSysctls.values {
		status.Sysctls[key] = recordedSysctl{
			Required: value.Required, Previous: value.Previous, RestoreOnExit: false,
		}
	}
	requiredSysctls.Unlock()

	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(runtimeDir, ".reconcile-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	var writeErrors []error
	if err := temporary.Chmod(0o600); err != nil {
		writeErrors = append(writeErrors, err)
	}
	if _, err := temporary.Write(data); err != nil {
		writeErrors = append(writeErrors, err)
	}
	if err := temporary.Sync(); err != nil {
		writeErrors = append(writeErrors, err)
	}
	if err := temporary.Close(); err != nil {
		writeErrors = append(writeErrors, err)
	}
	if err := errors.Join(writeErrors...); err != nil {
		return err
	}
	return os.Rename(temporaryName, reconcileStatusFile)
}

func readReconcileStatus() (reconcileStatus, error) {
	var status reconcileStatus
	raw, err := os.ReadFile(reconcileStatusFile)
	if err != nil {
		return status, err
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return status, err
	}
	return status, nil
}

func measureAndRecordDrift(wg wireGuardConfigurer, cfg *Config, applyErr error) {
	kernelDrift, firewallDrift := 0, 0
	if plan, err := buildKernelPlan(wg, cfg); err != nil {
		kernelDrift = 1
		applyErr = errors.Join(applyErr, fmt.Errorf("measure kernel drift: %w", err))
	} else {
		kernelDrift = len(plan.Operations) + len(plan.Drift)
	}
	if plan, err := buildFirewallPlan(cfg); err != nil {
		firewallDrift = 1
		applyErr = errors.Join(applyErr, fmt.Errorf("measure firewall drift: %w", err))
	} else {
		firewallDrift = len(plan)
	}
	if err := recordReconcileStatus(kernelDrift, firewallDrift, applyErr); err != nil {
		fmt.Fprintf(os.Stderr, "sakhtar-wg: record reconcile status: %v\n", err)
	}
}

// liveDrift measures drift NOW rather than reporting what was recorded at the
// last apply.
//
// The recorded gauges answer "did the apply leave the kernel correct", which is
// not the question someone running `status` is asking — they want to know
// whether it is correct *now*. The two diverge whenever something outside this
// daemon removes an object it owns, and that is not hypothetical: on
// 2026-08-09 every `ip rule fwmark ... lookup ...` had been flushed from
// sr-proxy, the entire SNI bypass had been egressing via the plain WAN for
// weeks, and `status` still printed `kernel_drift=0` because that was true at
// the last route refresh six hours earlier.
//
// Errors are reported rather than swallowed: "cannot measure" must not read the
// same as "measured zero", which is the whole failure mode above.
// effectiveConfig returns the config as the DAEMON applied it: the file plus the
// last-good fetched routes from `route_sources`.
//
// Diffing the raw file instead counts every auto-updated CIDR as drift. Measured
// on sr-proxy: 236 Meta prefixes, so a freshly restarted box reported
// kernel_drift=235 and a permanent DRIFTED — which is the stale `0` traded for
// noise nobody would read either. PfSync is disabled on the copy so this
// read-only path never constructs the SSH syncer.
func effectiveConfig(cfg *Config) *Config {
	base := *cfg
	base.PfSync.Enabled = false
	// Loading the route cache logs; on the daemon's startup path that line is
	// useful, in `status` it is a stray "routesrc: loaded cached routes" in the
	// middle of a report and reads like something went wrong.
	previous := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(previous)
	return NewRouteUpdater(&base, nil).Merge()
}

func liveDrift(wg wireGuardConfigurer, cfg *Config) (kernel, firewall int, err error) {
	cfg = effectiveConfig(cfg)
	plan, planErr := buildKernelPlan(wg, cfg)
	if planErr != nil {
		return 0, 0, fmt.Errorf("measure kernel drift: %w", planErr)
	}
	firewallPlan, firewallErr := buildFirewallPlan(cfg)
	if firewallErr != nil {
		return 0, 0, fmt.Errorf("measure firewall drift: %w", firewallErr)
	}
	return len(plan.Operations) + len(plan.Drift), len(firewallPlan), nil
}

func printRecordedReconcileStatus(wg wireGuardConfigurer, cfg *Config) {
	status, err := readReconcileStatus()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Printf("reconcile  unavailable (%v)\n", err)
		}
		return
	}
	result := "ok"
	if !status.LastApplySuccess {
		result = "failed: " + status.LastApplyError
	}
	fmt.Printf("reconcile  last_apply=%s result=%s kernel_drift=%d firewall_drift=%d\n",
		status.LastApplyTime.Format(time.RFC3339), result, status.KernelDriftGauge, status.FirewallDriftGauge)
	// The line above is history; this one is the answer to "is it right now".
	if kernel, firewall, driftErr := liveDrift(wg, cfg); driftErr != nil {
		fmt.Printf("           live       UNMEASURED (%v)\n", driftErr)
	} else {
		verdict := "in sync"
		if kernel != 0 || firewall != 0 {
			verdict = "DRIFTED — run `systemctl reload sakhtar-wg` to reconcile"
		}
		fmt.Printf("           live       kernel_drift=%d firewall_drift=%d  %s\n",
			kernel, firewall, verdict)
	}
	keys := make([]string, 0, len(status.Sysctls))
	for key := range status.Sysctls {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := status.Sysctls[key]
		fmt.Printf("            sysctl=%s required=%s previous=%s restore_on_exit=%t\n",
			key, value.Required, value.Previous, value.RestoreOnExit)
	}
}
