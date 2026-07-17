// Package dns provides bounded, generation-aware DNS resolution caching.
// It intentionally has no dependency on the daemon's configuration or proxy
// packages so its capacity, expiry, and cancellation invariants are testable in
// isolation.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type RCode uint8

const (
	RCodeSuccess RCode = iota
	RCodeNXDOMAIN
	RCodeNODATA
	RCodeTransient
)

func (r RCode) String() string {
	switch r {
	case RCodeSuccess:
		return "positive"
	case RCodeNXDOMAIN:
		return "nxdomain"
	case RCodeNODATA:
		return "nodata"
	case RCodeTransient:
		return "transient"
	default:
		return "unknown"
	}
}

type Family uint8

const (
	FamilyAny Family = iota
	FamilyIPv4
	FamilyIPv6
)

// Result is immutable at package boundaries: Cache.Resolve always copies the
// address slice before returning it to a caller.
type Result struct {
	Addrs     []netip.Addr
	ExpiresAt time.Time
	RCode     RCode
}

func (r Result) clone() Result {
	r.Addrs = append([]netip.Addr(nil), r.Addrs...)
	return r
}

// Query contains every input that can change resolver meaning. Egress and
// Resolver are identities used only in cache keys; metrics never expose them.
type Query struct {
	Host       string
	Family     Family
	Egress     string
	Resolver   string
	Generation uint64
}

type key struct {
	host       string
	family     Family
	egress     string
	resolver   string
	generation uint64
}

func makeKey(q Query) (key, error) {
	host := strings.ToLower(strings.TrimSuffix(q.Host, "."))
	if host == "" || strings.TrimSpace(host) != host {
		return key{}, errors.New("dns: invalid empty or whitespace hostname")
	}
	if q.Family > FamilyIPv6 {
		return key{}, fmt.Errorf("dns: invalid address family %d", q.Family)
	}
	return key{host: host, family: q.Family, egress: q.Egress, resolver: q.Resolver, generation: q.Generation}, nil
}

// Resolver returns authoritative negative answers as a Result with nil error.
// Timeouts, transport errors, SERVFAIL, and other retryable failures return an
// error and are classified by Cache as transient.
type Resolver interface {
	Resolve(context.Context, Query) (Result, error)
}

type ResolverFunc func(context.Context, Query) (Result, error)

func (f ResolverFunc) Resolve(ctx context.Context, q Query) (Result, error) {
	return f(ctx, q)
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type StalePolicy string

const (
	StaleNever     StalePolicy = "never"
	StaleTransient StalePolicy = "transient"
)

type Policy struct {
	PositiveCapacity    int
	NegativeCapacity    int
	MaxPending          int
	MinPositiveTTL      time.Duration
	MaxPositiveTTL      time.Duration
	NegativeTTL         time.Duration
	TransientFailureTTL time.Duration
	StaleWindow         time.Duration
	StalePolicy         StalePolicy
	ResolverTimeout     time.Duration
}

func (p Policy) Validate() error {
	switch {
	case p.PositiveCapacity <= 0:
		return errors.New("dns: positive capacity must be greater than zero")
	case p.NegativeCapacity <= 0:
		return errors.New("dns: negative capacity must be greater than zero")
	case p.MaxPending <= 0:
		return errors.New("dns: max pending must be greater than zero")
	case p.MinPositiveTTL <= 0:
		return errors.New("dns: minimum positive TTL must be greater than zero")
	case p.MaxPositiveTTL < p.MinPositiveTTL:
		return errors.New("dns: maximum positive TTL must be at least the minimum")
	case p.NegativeTTL <= 0:
		return errors.New("dns: negative TTL must be greater than zero")
	case p.TransientFailureTTL <= 0:
		return errors.New("dns: transient failure TTL must be greater than zero")
	case p.StaleWindow < 0:
		return errors.New("dns: stale window must not be negative")
	case p.StalePolicy != StaleNever && p.StalePolicy != StaleTransient:
		return fmt.Errorf("dns: unsupported stale policy %q", p.StalePolicy)
	case p.ResolverTimeout <= 0:
		return errors.New("dns: resolver timeout must be greater than zero")
	}
	return nil
}

var ErrPendingLimit = errors.New("dns: pending resolution limit reached")

// ResolveError preserves the transient resolver error while giving callers a
// stable class they can inspect without parsing error text.
type ResolveError struct {
	Err error
}

func (e *ResolveError) Error() string {
	if e == nil || e.Err == nil {
		return "dns: transient resolution failure"
	}
	return "dns: transient resolution failure: " + e.Err.Error()
}

func (e *ResolveError) Unwrap() error { return e.Err }
