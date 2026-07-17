// Command loadgen drives raw TCP TLS ClientHello and HTTP Host workloads
// against a running sakhtar-wg proxy. It intentionally does not terminate TLS
// or use net/http for the datapath under test.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type options struct {
	target        string
	managementURL string
	protocol      string
	host          string
	requests      int
	concurrency   int
	timeout       time.Duration
	hold          time.Duration
	readBytes     int
	slowloris     int
	reloadPID     int
	reloadAfter   time.Duration
	output        string
}

type summary struct {
	StartedAt               time.Time `json:"started_at"`
	DurationSeconds         float64   `json:"duration_seconds"`
	Attempted               uint64    `json:"attempted"`
	WriteSucceeded          uint64    `json:"write_succeeded"`
	ResponseSucceeded       uint64    `json:"response_succeeded"`
	Failed                  uint64    `json:"failed"`
	FailedAfterReload       uint64    `json:"failed_after_reload"`
	ConnectionsPerSecond    float64   `json:"connections_per_second"`
	SetupLatencyP50Millis   float64   `json:"setup_latency_p50_ms"`
	SetupLatencyP95Millis   float64   `json:"setup_latency_p95_ms"`
	SetupLatencyP99Millis   float64   `json:"setup_latency_p99_ms"`
	SetupLatencyMaxMillis   float64   `json:"setup_latency_max_ms"`
	ReloadAttempted         bool      `json:"reload_attempted"`
	ReloadAt                time.Time `json:"reload_at,omitempty"`
	ReloadError             string    `json:"reload_error,omitempty"`
	ManagementSnapshotError string    `json:"management_snapshot_error,omitempty"`
}

type report struct {
	Schema   string            `json:"schema"`
	Metadata metadata          `json:"metadata"`
	Scenario scenario          `json:"scenario"`
	Summary  summary           `json:"summary"`
	Metrics  metricComparison  `json:"metrics"`
	Errors   map[string]uint64 `json:"errors"`
}

type metadata struct {
	GeneratedAt time.Time `json:"generated_at"`
	Toolchain   string    `json:"toolchain"`
	GOOS        string    `json:"goos"`
	GOARCH      string    `json:"goarch"`
	CPUs        int       `json:"cpus"`
}

type scenario struct {
	Target        string        `json:"target"`
	ManagementURL string        `json:"management_url,omitempty"`
	Protocol      string        `json:"protocol"`
	Host          string        `json:"host"`
	Requests      int           `json:"requests"`
	Concurrency   int           `json:"concurrency"`
	Timeout       time.Duration `json:"timeout"`
	Hold          time.Duration `json:"hold"`
	ReadBytes     int           `json:"read_bytes"`
	Slowloris     int           `json:"slowloris_bytes"`
}

type metricComparison struct {
	Before  map[string]float64 `json:"before,omitempty"`
	After   map[string]float64 `json:"after,omitempty"`
	Delta   map[string]float64 `json:"delta,omitempty"`
	Derived map[string]float64 `json:"derived,omitempty"`
}

type sample struct {
	setup    time.Duration
	wrote    bool
	response bool
	errClass string
	after    bool
}

type reloadOutcome struct {
	at  time.Time
	err error
}

func main() {
	var o options
	flag.StringVar(&o.target, "target", "127.0.0.1:443", "proxy host:port")
	flag.StringVar(&o.managementURL, "management-url", "", "optional management base URL, for example http://127.0.0.1:9090")
	flag.StringVar(&o.protocol, "protocol", "tls", "fixture protocol: tls or http")
	flag.StringVar(&o.host, "host", "example.com", "TLS SNI or HTTP Host")
	flag.IntVar(&o.requests, "requests", 1000, "total connections")
	flag.IntVar(&o.concurrency, "concurrency", 100, "parallel workers")
	flag.DurationVar(&o.timeout, "timeout", 10*time.Second, "per-connection deadline")
	flag.DurationVar(&o.hold, "hold", 0, "hold each connection open after writing")
	flag.IntVar(&o.readBytes, "read-bytes", 0, "bytes to read after write; zero measures setup/write only")
	flag.IntVar(&o.slowloris, "slowloris-bytes", 0, "send only this many fixture bytes, one per second")
	flag.IntVar(&o.reloadPID, "reload-pid", 0, "send SIGHUP to this local PID during traffic")
	flag.DurationVar(&o.reloadAfter, "reload-after", 0, "delay before SIGHUP; requires -reload-pid")
	flag.StringVar(&o.output, "output", "-", "JSON report path or - for stdout")
	flag.Parse()
	if err := validate(o); err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(2)
	}
	result, err := run(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(1)
	}
	if err := writeReport(o.output, result); err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(1)
	}
}

func validate(o options) error {
	if _, _, err := net.SplitHostPort(o.target); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if o.protocol != "tls" && o.protocol != "http" {
		return errors.New("protocol must be tls or http")
	}
	if o.host == "" || len(o.host) > 253 {
		return errors.New("host must contain 1-253 bytes")
	}
	if o.requests < 1 || o.concurrency < 1 || o.concurrency > o.requests {
		return errors.New("requests must be positive and concurrency must be between 1 and requests")
	}
	if o.timeout <= 0 || o.hold < 0 || o.readBytes < 0 || o.slowloris < 0 {
		return errors.New("timeouts, read bytes, and slowloris bytes must be non-negative")
	}
	if o.reloadAfter > 0 && o.reloadPID <= 0 {
		return errors.New("reload-after requires reload-pid")
	}
	return nil
}

func run(o options) (report, error) {
	fixture := httpFixture(o.host)
	if o.protocol == "tls" {
		fixture = tlsFixture(o.host)
	}
	if o.slowloris > len(fixture) {
		return report{}, fmt.Errorf("slowloris-bytes %d exceeds fixture length %d", o.slowloris, len(fixture))
	}
	before, beforeErr := scrapeMetrics(o.managementURL)
	started := time.Now().UTC()
	var reloadOccurred atomic.Bool
	reloadResult := make(chan reloadOutcome, 1)
	if o.reloadPID > 0 {
		go func() {
			if o.reloadAfter > 0 {
				timer := time.NewTimer(o.reloadAfter)
				defer timer.Stop()
				<-timer.C
			}
			process, err := os.FindProcess(o.reloadPID)
			if err == nil {
				err = process.Signal(syscall.SIGHUP)
			}
			reloadOccurred.Store(true)
			reloadResult <- reloadOutcome{at: time.Now().UTC(), err: err}
		}()
	}

	jobs := make(chan int)
	samples := make(chan sample, o.requests)
	var workers sync.WaitGroup
	for range o.concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range jobs {
				samples <- connect(o, fixture, &reloadOccurred)
			}
		}()
	}
	go func() {
		for i := 0; i < o.requests; i++ {
			jobs <- i
		}
		close(jobs)
		workers.Wait()
		close(samples)
	}()

	result := report{
		Schema:   "sakhtar-wg-load/v1",
		Metadata: metadata{GeneratedAt: time.Now().UTC(), Toolchain: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUs: runtime.NumCPU()},
		Scenario: scenario{Target: o.target, ManagementURL: o.managementURL, Protocol: o.protocol, Host: o.host, Requests: o.requests, Concurrency: o.concurrency, Timeout: o.timeout, Hold: o.hold, ReadBytes: o.readBytes, Slowloris: o.slowloris},
		Errors:   make(map[string]uint64),
	}
	latencies := make([]time.Duration, 0, o.requests)
	for observation := range samples {
		result.Summary.Attempted++
		if observation.wrote {
			result.Summary.WriteSucceeded++
			latencies = append(latencies, observation.setup)
		}
		if observation.response {
			result.Summary.ResponseSucceeded++
		}
		if observation.errClass != "" {
			result.Summary.Failed++
			result.Errors[observation.errClass]++
			if observation.after {
				result.Summary.FailedAfterReload++
			}
		}
	}
	finished := time.Now()
	result.Summary.StartedAt = started
	result.Summary.DurationSeconds = finished.Sub(started).Seconds()
	if result.Summary.DurationSeconds > 0 {
		result.Summary.ConnectionsPerSecond = float64(result.Summary.WriteSucceeded) / result.Summary.DurationSeconds
	}
	result.Summary.SetupLatencyP50Millis = percentile(latencies, 0.50)
	result.Summary.SetupLatencyP95Millis = percentile(latencies, 0.95)
	result.Summary.SetupLatencyP99Millis = percentile(latencies, 0.99)
	result.Summary.SetupLatencyMaxMillis = percentile(latencies, 1)
	if o.reloadPID > 0 {
		result.Summary.ReloadAttempted = true
		outcome := <-reloadResult
		result.Summary.ReloadAt = outcome.at
		if outcome.err != nil {
			result.Summary.ReloadError = outcome.err.Error()
		}
	}
	after, afterErr := scrapeMetrics(o.managementURL)
	result.Metrics = compareMetrics(before, after, result.Summary.DurationSeconds)
	if snapshotErr := errors.Join(beforeErr, afterErr); snapshotErr != nil {
		result.Summary.ManagementSnapshotError = snapshotErr.Error()
	}
	return result, nil
}

func connect(o options, fixture []byte, reloadOccurred *atomic.Bool) sample {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", o.target)
	if err != nil {
		return sample{errClass: classify(err), after: reloadOccurred.Load()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(o.timeout))
	if o.slowloris > 0 {
		for _, value := range fixture[:o.slowloris] {
			if _, err = conn.Write([]byte{value}); err != nil {
				return sample{errClass: classify(err), after: reloadOccurred.Load()}
			}
			time.Sleep(time.Second)
		}
	} else {
		_, err = conn.Write(fixture)
	}
	if err != nil {
		return sample{errClass: classify(err), after: reloadOccurred.Load()}
	}
	observation := sample{setup: time.Since(started), wrote: true}
	if o.hold > 0 {
		timer := time.NewTimer(o.hold)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			observation.errClass = classify(ctx.Err())
			observation.after = reloadOccurred.Load()
			return observation
		}
	}
	if o.readBytes > 0 {
		buffer := make([]byte, o.readBytes)
		if _, err = io.ReadFull(conn, buffer); err != nil {
			observation.errClass = classify(err)
			observation.after = reloadOccurred.Load()
			return observation
		}
		observation.response = true
	}
	return observation
}

func classify(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return "timeout"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "connection_reset"
	}
	return "other"
}

func httpFixture(host string) []byte {
	return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: sakhtar-wg-loadgen/1\r\nConnection: close\r\n\r\n")
}

func tlsFixture(host string) []byte {
	name := []byte(host)
	sniBody := make([]byte, 2+1+2+len(name))
	binary.BigEndian.PutUint16(sniBody[0:2], uint16(1+2+len(name)))
	sniBody[2] = 0
	binary.BigEndian.PutUint16(sniBody[3:5], uint16(len(name)))
	copy(sniBody[5:], name)
	extensions := appendExtension(nil, 0x0000, sniBody)
	extensions = appendExtension(extensions, 0x002b, []byte{0x02, 0x03, 0x04})
	extensions = appendExtension(extensions, 0x000a, []byte{0x00, 0x02, 0x00, 0x1d})
	extensions = appendExtension(extensions, 0x000d, []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04})
	body := []byte{0x03, 0x03}
	random := sha256.Sum256([]byte("sakhtar-wg-loadgen:" + host))
	body = append(body, random[:]...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02)
	body = append(body, 0x01, 0x00)
	body = appendUint16(body, len(extensions))
	body = append(body, extensions...)
	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x01}
	record = appendUint16(record, len(handshake))
	return append(record, handshake...)
}

func appendExtension(dst []byte, kind uint16, body []byte) []byte {
	dst = append(dst, byte(kind>>8), byte(kind))
	dst = appendUint16(dst, len(body))
	return append(dst, body...)
}

func appendUint16(dst []byte, value int) []byte {
	return append(dst, byte(value>>8), byte(value))
}

func scrapeMetrics(baseURL string) (map[string]float64, error) {
	if baseURL == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics HTTP %d", response.StatusCode)
	}
	result := make(map[string]float64)
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 8<<20))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "sakhtar_wg_") {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err == nil {
			result[fields[0]] = value
		}
	}
	return result, scanner.Err()
}

func compareMetrics(before, after map[string]float64, duration float64) metricComparison {
	comparison := metricComparison{Before: before, After: after, Delta: map[string]float64{}, Derived: map[string]float64{}}
	for key, value := range after {
		comparison.Delta[key] = value - before[key]
	}
	var resolutions, rejections float64
	for key, value := range comparison.Delta {
		if strings.HasPrefix(key, "sakhtar_wg_dns_resolutions_total") {
			resolutions += value
		}
		if strings.HasPrefix(key, "sakhtar_wg_proxy_rejections_total") {
			rejections += value
		}
	}
	comparison.Derived["dns_resolutions"] = resolutions
	comparison.Derived["rejections"] = rejections
	if duration > 0 {
		comparison.Derived["dns_qps"] = resolutions / duration
	}
	return comparison
}

func percentile(values []time.Duration, fraction float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := int(float64(len(values)-1) * fraction)
	return float64(values[index]) / float64(time.Millisecond)
}

func writeReport(path string, value report) error {
	var writer io.Writer = os.Stdout
	var file *os.File
	if path != "-" {
		var err error
		file, err = os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		writer = file
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
