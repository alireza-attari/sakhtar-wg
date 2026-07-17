//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"github.com/alireza-attari/sakhtar-wg/internal/observability"
	"golang.zx2c4.com/wireguard/wgctrl"
)

const (
	defaultConfig = "/etc/sakhtar-wg/config.yaml"
	runtimeDir    = "/run/sakhtar-wg"
	pidFile       = runtimeDir + "/sakhtar-wg.pid"
)

func main() {
	logger := observability.NewJSONLogger(os.Stderr, slog.LevelInfo)
	slog.SetDefault(logger)
	log.SetFlags(0)
	log.SetOutput(slog.NewLogLogger(logger.Handler(), slog.LevelInfo).Writer())

	fs := flag.NewFlagSet("sakhtar-wg", flag.ExitOnError)
	cfgPath := fs.String("c", defaultConfig, "config file path")
	versionJSON := fs.Bool("json", false, "print machine-readable version metadata (version command only)")
	fs.Usage = usage
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "up":
		mustRoot(cmd)
		runUp(*cfgPath)
	case "down":
		mustRoot(cmd)
		runDown(*cfgPath)
	case "status":
		runStatus(*cfgPath)
	case "plan":
		runPlan(*cfgPath)
	case "reload":
		runReload()
	case "version", "-v", "--version":
		if err := writeVersion(os.Stdout, *versionJSON); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sakhtar-wg — lightweight WireGuard tunnels + SNI/Host egress proxy

usage:
  sakhtar-wg up      [-c config]   bring tunnels up and run the proxy (foreground)
  sakhtar-wg down    [-c config]   tear tunnels down
	  sakhtar-wg status  [-c config]   show tunnel handshake/transfer
	  sakhtar-wg plan    [-c config]   print a redacted deterministic diff (no mutation)
  sakhtar-wg reload                signal a running 'up' to re-read its config (SIGHUP)
  sakhtar-wg version [-json]

default config: `+defaultConfig+"\n")
}

func runUp(path string) {
	cfg, err := LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	registry := observability.NewRegistry()
	registry.SetComponent("config", true, true, "ok", nil)

	// Refuse to run twice: a second 'up' would tear down the first instance's
	// tunnels while converging. The lock is held for the process lifetime.
	lock := acquireSingleton()
	defer func() {
		_ = lock.Close()
		_ = os.Remove(pidFile)
	}()

	wg, err := wgctrl.New()
	if err != nil {
		log.Fatalf("open wgctrl: %v", err)
	}
	defer wg.Close()

	if err := validateKernelReservations(cfg); err != nil {
		log.Fatalf("kernel ownership allocation: %v", err)
	}
	if cfg.Gateway.Enabled {
		if _, err := compileGatewayRuleset(cfg); err != nil {
			log.Fatalf("gateway policy preflight: %v", err)
		}
	}
	for _, t := range cfg.Tunnels {
		if err := tunnelUp(wg, t); err != nil {
			if cleanupErr := teardown(cfg); cleanupErr != nil {
				log.Printf("cleanup after failed startup: %v", cleanupErr)
				err = errors.Join(err, cleanupErr)
			}
			measureAndRecordDrift(wg, cfg, err)
			log.Fatalf("bring up %s: %v", t.Name, err)
		}
		log.Printf("tunnel %s up (fwmark %d, table %d)", t.Name, t.Fwmark, t.Table)
	}

	if err := gatewayUp(cfg); err != nil {
		if cleanupErr := teardown(cfg); cleanupErr != nil {
			log.Printf("cleanup after failed gateway apply: %v", cleanupErr)
			err = errors.Join(err, cleanupErr)
		}
		measureAndRecordDrift(wg, cfg, err)
		log.Fatalf("gateway: %v", err)
	}
	measureAndRecordDrift(wg, cfg, nil)
	if cfg.Gateway.Enabled {
		log.Printf("gateway: forwarding %v out tunnels", cfg.Gateway.ClientCIDRs)
	}

	// Health monitor for tunnel groups: polls handshake freshness and steers each
	// group's live SO_MARK. Rebuilt on SIGHUP so group topology changes take
	// effect; runs under its own cancel so a reload can restart it cleanly.
	hmCtx, hmCancel := context.WithCancel(context.Background())
	hm, err := NewHealthMonitor(cfg, healthObserver(registry, cfg.HealthProbe.Enabled))
	if err != nil {
		if cleanupErr := teardown(cfg); cleanupErr != nil {
			log.Printf("cleanup after failed health startup: %v", cleanupErr)
		}
		log.Fatalf("health monitor: %v", err)
	}
	hmDone := runHealthMonitor(hmCtx, hm)
	if len(cfg.Groups) > 0 {
		log.Printf("health: monitoring %d group(s) every %ds", len(cfg.Groups), cfg.HealthInterval)
	}

	srv := NewServer(cfg, hm)
	if err := srv.Start(cfg); err != nil {
		hmCancel()
		<-hmDone
		_ = hm.Close()
		if cleanupErr := teardown(cfg); cleanupErr != nil {
			log.Printf("cleanup after failed proxy startup: %v", cleanupErr)
		}
		log.Fatalf("start proxy: %v", err)
	}
	registry.SetActiveGeneration(srv.Generation())
	collectOperationalState(registry, srv)
	var list *ListServer
	if cfg.Gateway.Enabled && cfg.Gateway.ListListen != "" {
		list = NewListServer(cfg)
		if err := list.Start(cfg.Gateway.ListListen); err != nil {
			srv.Stop()
			hmCancel()
			<-hmDone
			_ = hm.Close()
			if cleanupErr := teardown(cfg); cleanupErr != nil {
				log.Printf("cleanup after failed list-server startup: %v", cleanupErr)
			}
			log.Fatalf("start list server: %v", err)
		}
		registry.SetComponent("list_server", true, true, "ok", nil)
	}

	var management *observability.ManagementServer
	if !cfg.Management.Disabled {
		management, err = observability.NewManagementServer(managementConfig(cfg.Management), registry, func() { collectOperationalState(registry, srv) }, slog.Default())
		if err == nil {
			err = management.Start()
		}
		if err != nil {
			if list != nil {
				list.Stop()
			}
			hmCancel()
			<-hmDone
			_ = hm.Close()
			srv.Stop()
			if cleanupErr := teardown(cfg); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
			log.Fatalf("start management server: %v", err)
		}
		registry.SetComponent("management", true, true, "ok", nil)
	}

	// Route-source auto-update: fetches provider CIDR lists in the background and
	// pushes merged configs over applyCh. All kernel mutation still happens here
	// on the main goroutine, so it never races a SIGHUP reload.
	ctx, cancel := context.WithCancel(context.Background())
	probeCtx, probeCancel := context.WithCancel(context.Background())
	_ = startActiveProbe(probeCtx, cfg, registry)
	applyCh := make(chan *Config, 1)
	var updater *RouteUpdater
	if needsRouteUpdater(cfg) {
		updater = NewRouteUpdater(cfg, applyCh, registry)
		go updater.Run(ctx)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
loop:
	for {
		select {
		case merged := <-applyCh:
			// Route-only refresh from the updater: reconcile L3 routes and the
			// served list without disturbing the WireGuard devices.
			applyRoutes(merged)
			if list != nil {
				list.Reload(merged)
			}
			cfg = merged
		case s := <-sig:
			if s == syscall.SIGHUP {
				reloadStarted := time.Now()
				newCfg, err := LoadConfig(path)
				if err != nil {
					recordReload(registry, srv, reloadStarted, err)
					log.Printf("reload: %v (keeping current config)", err)
					continue
				}
				if err := reloadRequiresRestart(cfg, newCfg); err != nil {
					recordReload(registry, srv, reloadStarted, err)
					log.Printf("reload: %v (keeping current config)", err)
					continue
				}
				// Fold in the last-good fetched routes so a static-config reload
				// never drops auto-updated CIDRs, and re-fetch in the background.
				next := newCfg
				if updater != nil {
					next = updater.MergeBase(newCfg)
				}
				// Build the candidate health topology without stopping the active
				// generation. It is started only after the reload commits.
				candidateHM, err := NewHealthMonitor(next, healthObserver(registry, next.HealthProbe.Enabled))
				if err != nil {
					recordReload(registry, srv, reloadStarted, err)
					log.Printf("reload: health monitor: %v (keeping current config)", err)
					continue
				}
				if err := applyReload(wg, cfg, next, srv, candidateHM); err != nil {
					_ = candidateHM.Close()
					measureAndRecordDrift(wg, cfg, err)
					recordReload(registry, srv, reloadStarted, err)
					log.Printf("reload: %v (keeping current config)", err)
					continue
				}
				hmCancel()
				<-hmDone
				_ = hm.Close()
				hm = candidateHM
				hmCtx, hmCancel = context.WithCancel(context.Background())
				hmDone = runHealthMonitor(hmCtx, hm)
				if updater != nil {
					updater.SetBase(newCfg)
				} else if needsRouteUpdater(newCfg) {
					updater = NewRouteUpdater(newCfg, applyCh, registry)
					go updater.Run(ctx)
				}
				if list != nil {
					list.Reload(next)
				}
				cfg = next
				probeCancel()
				probeCtx, probeCancel = context.WithCancel(context.Background())
				_ = startActiveProbe(probeCtx, cfg, registry)
				measureAndRecordDrift(wg, cfg, nil)
				collectOperationalState(registry, srv)
				recordReload(registry, srv, reloadStarted, nil)
				log.Print("reloaded")
				continue
			}
			slog.Info("lifecycle.shutdown_started", "component", "runtime", "generation", srv.Generation(), "signal", s.String(), "outcome", "started")
			break loop
		}
	}
	cancel()
	probeCancel()
	if management != nil {
		if err := management.Shutdown(context.Background()); err != nil {
			log.Printf("management shutdown: %v", err)
		}
	}
	hmCancel()
	<-hmDone
	_ = hm.Close()
	if list != nil {
		list.Stop()
	}
	srv.Stop()
	if err := teardown(cfg); err != nil {
		log.Printf("shutdown cleanup drift: %v", err)
	}
}

func reloadRequiresRestart(old, next *Config) error {
	if old.Management != next.Management {
		return errors.New("management listener settings changed; restart required")
	}
	if old.Proxy.HTTPSListen != next.Proxy.HTTPSListen || old.Proxy.HTTPListen != next.Proxy.HTTPListen {
		return errors.New("proxy listener addresses changed; restart required")
	}
	oldList, nextList := "", ""
	if old.Gateway.Enabled {
		oldList = old.Gateway.ListListen
	}
	if next.Gateway.Enabled {
		nextList = next.Gateway.ListListen
	}
	if oldList != nextList {
		return errors.New("gateway list listener changed; restart required")
	}
	return nil
}

// applyReload converges tunnels to newCfg (add/reconfigure/remove) and swaps the
// proxy's routing table. Tunnels whose spec is unchanged are left running
// untouched, so a routine rule-only reload never resets a live tunnel's peer
// (no counter reset, no re-handshake).
func applyReload(wg *wgctrl.Client, old, next *Config, srv *Server, hm *HealthMonitor) error {
	if err := validateKernelReservations(old); err != nil {
		return fmt.Errorf("current kernel ownership is ambiguous: %w", err)
	}
	if next.Gateway.Enabled {
		if _, err := compileGatewayRuleset(next); err != nil {
			return fmt.Errorf("candidate gateway policy: %w", err)
		}
	}
	oldByName := make(map[string]Tunnel, len(old.Tunnels))
	for _, t := range old.Tunnels {
		oldByName[t.Name] = t
	}
	keep := map[string]bool{}
	for _, t := range next.Tunnels {
		keep[t.Name] = true
		prev, existed := oldByName[t.Name]
		if existed && reflect.DeepEqual(prev, t) {
			continue // unchanged — don't disturb the live tunnel
		}
		if err := tunnelUp(wg, t); err != nil {
			return rollbackKernelApply(wg, old, next, fmt.Errorf("apply tunnel %s: %w", t.Name, err))
		}
		if existed && prev.Address != t.Address {
			if err := deleteExactOwnedAddress(prev); err != nil {
				return rollbackKernelApply(wg, old, next, fmt.Errorf("remove old address from %s: %w", t.Name, err))
			}
		}
		if existed && prev.Table != t.Table {
			if err := deleteOwnedDefaultRoute(prev); err != nil {
				return rollbackKernelApply(wg, old, next, fmt.Errorf("remove old default route from %s: %w", t.Name, err))
			}
		}
		if existed && (prev.RulePriority != t.RulePriority || prev.Fwmark != t.Fwmark || prev.FwmarkMask != t.FwmarkMask || prev.Table != t.Table) {
			if err := deleteOwnedRule(prev); err != nil {
				return rollbackKernelApply(wg, old, next, fmt.Errorf("remove old rule from %s: %w", t.Name, err))
			}
		}
		log.Printf("tunnel %s reconfigured", t.Name)
	}
	if old.Gateway.Enabled && !next.Gateway.Enabled {
		if err := gatewayDown(old); err != nil {
			return rollbackKernelApply(wg, old, next, fmt.Errorf("disable gateway: %w", err))
		}
	} else if err := gatewayUp(next); err != nil {
		return rollbackKernelApply(wg, old, next, fmt.Errorf("apply gateway: %w", err))
	}
	srv.Reload(next, hm)
	for _, t := range old.Tunnels {
		if !keep[t.Name] {
			if err := tunnelDown(t); err != nil {
				log.Printf("reload: deferred cleanup drift for %s: %v", t.Name, err)
			} else {
				log.Printf("tunnel %s removed", t.Name)
			}
		}
	}
	return nil
}

func rollbackKernelApply(wg *wgctrl.Client, old, attempted *Config, applyErr error) error {
	var repair []error
	oldByName := make(map[string]Tunnel, len(old.Tunnels))
	for _, tunnel := range old.Tunnels {
		oldByName[tunnel.Name] = tunnel
	}
	for _, tunnel := range attempted.Tunnels {
		previous, existed := oldByName[tunnel.Name]
		if !existed {
			if err := tunnelDown(tunnel); err != nil {
				repair = append(repair, fmt.Errorf("remove uncommitted %s: %w", tunnel.Name, err))
			}
			continue
		}
		if previous.PrivateKey == tunnel.PrivateKey && previous.Address != tunnel.Address {
			if err := deleteExactOwnedAddress(tunnel); err != nil {
				repair = append(repair, fmt.Errorf("remove uncommitted address from %s: %w", tunnel.Name, err))
			}
		}
		if previous.PrivateKey == tunnel.PrivateKey && (previous.RulePriority != tunnel.RulePriority || previous.Fwmark != tunnel.Fwmark || previous.FwmarkMask != tunnel.FwmarkMask || previous.Table != tunnel.Table) {
			if err := deleteOwnedRule(tunnel); err != nil {
				repair = append(repair, fmt.Errorf("remove uncommitted rule from %s: %w", tunnel.Name, err))
			}
		}
		if previous.PrivateKey == tunnel.PrivateKey && previous.Table != tunnel.Table {
			if err := deleteOwnedDefaultRoute(tunnel); err != nil {
				repair = append(repair, fmt.Errorf("remove uncommitted default route from %s: %w", tunnel.Name, err))
			}
		}
	}
	for _, tunnel := range old.Tunnels {
		if err := tunnelUp(wg, tunnel); err != nil {
			repair = append(repair, fmt.Errorf("repair %s: %w", tunnel.Name, err))
		}
	}
	if old.Gateway.Enabled {
		if err := gatewayUp(old); err != nil {
			repair = append(repair, fmt.Errorf("repair gateway: %w", err))
		}
	} else if err := gatewayDown(attempted); err != nil {
		repair = append(repair, fmt.Errorf("remove uncommitted gateway: %w", err))
	}
	return errors.Join(applyErr, errors.Join(repair...))
}

func runDown(path string) {
	cfg, err := LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	if err := teardown(cfg); err != nil {
		_ = recordReconcileStatus(1, 1, err)
		log.Fatalf("down with cleanup drift: %v", err)
	}
	_ = recordReconcileStatus(0, 0, nil)
	log.Print("down")
}

func teardown(cfg *Config) error {
	var cleanup []error
	if err := gatewayDown(cfg); err != nil {
		cleanup = append(cleanup, err)
	}
	for _, t := range cfg.Tunnels {
		if err := tunnelDown(t); err != nil {
			cleanup = append(cleanup, err)
		}
	}
	return errors.Join(cleanup...)
}

func runStatus(path string) {
	cfg, err := LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	wg, err := wgctrl.New()
	if err != nil {
		log.Fatalf("open wgctrl: %v", err)
	}
	defer wg.Close()
	printStatus(wg, cfg)
	printRecordedReconcileStatus()
}

func runReload() {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		log.Fatalf("no running instance (%s): %v", pidFile, err)
	}
	pid, err := strconv.Atoi(string(bytesTrim(data)))
	if err != nil {
		log.Fatalf("bad pid file: %v", err)
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		log.Fatalf("signal pid %d: %v", pid, err)
	}
	fmt.Printf("sent SIGHUP to %d\n", pid)
}

// acquireSingleton takes an exclusive flock on the pid file and writes our pid
// into it, keeping the fd open for the process lifetime. Returns the locked file
// (close it to release). Fatal if another instance already holds the lock.
func acquireSingleton() *os.File {
	if err := os.MkdirAll(filepath.Dir(pidFile), 0o700); err != nil {
		log.Fatalf("create runtime directory: %v", err)
	}
	f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		log.Fatalf("open %s: %v", pidFile, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		log.Fatalf("another sakhtar-wg instance is already running (%s is locked)", pidFile)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	return f
}

func mustRoot(cmd string) {
	if os.Geteuid() != 0 {
		log.Fatalf("%q needs root (netlink + SO_MARK + privileged ports)", cmd)
	}
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}
