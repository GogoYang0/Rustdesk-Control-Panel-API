package api

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// loginGuard implements the two-track login protection:
//   - per-IP token bucket: 5 attempts per minute, then 429.
//   - per account+IP failure counter: 5 failures within 15 minutes locks that
//     pair out, without locking the account itself.
//
// Both maps are bounded: idle entries are swept once the map grows past
// maxTrackedKeys, so a client rotating source addresses cannot grow memory
// without limit (CWE-770).
type loginGuard struct {
	mu       sync.Mutex
	limiters map[string]*ipEntry
	failures map[string]*failureWindow
	now      func() time.Time
}

type ipEntry struct {
	lim  *rate.Limiter
	last time.Time
}

type failureWindow struct {
	count int
	since time.Time
}

const (
	ipRatePerMinute = 5
	ipBurst         = 5
	failureLimit    = 5
	failureWindowD  = 15 * time.Minute
	idleWindow      = 10 * time.Minute
	maxTrackedKeys  = 4096
)

func newLoginGuard() *loginGuard {
	return &loginGuard{
		limiters: map[string]*ipEntry{},
		failures: map[string]*failureWindow{},
		now:      time.Now,
	}
}

// allowIP reports whether the IP may attempt another login.
func (g *loginGuard) allowIP(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	if len(g.limiters) >= maxTrackedKeys {
		g.sweepLocked(now)
	}

	entry, ok := g.limiters[ip]
	if !ok {
		entry = &ipEntry{lim: rate.NewLimiter(rate.Every(time.Minute/ipRatePerMinute), ipBurst)}
		g.limiters[ip] = entry
	}
	entry.last = now
	return entry.lim.Allow()
}

// locked reports whether the account+IP pair is currently locked out.
func (g *loginGuard) locked(account, ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	key := account + "\x00" + ip
	w, ok := g.failures[key]
	if !ok {
		return false
	}
	if g.now().Sub(w.since) > failureWindowD {
		delete(g.failures, key)
		return false
	}
	return w.count >= failureLimit
}

// recordFailure increments the failure counter for the account+IP pair.
func (g *loginGuard) recordFailure(account, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	if len(g.failures) >= maxTrackedKeys {
		g.sweepLocked(now)
	}

	key := account + "\x00" + ip
	w, ok := g.failures[key]
	if !ok || now.Sub(w.since) > failureWindowD {
		g.failures[key] = &failureWindow{count: 1, since: now}
		return
	}
	w.count++
}

// reset clears the failure counter after a successful login.
func (g *loginGuard) reset(account, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, account+"\x00"+ip)
}

// sweepLocked drops idle limiters and elapsed failure windows.
func (g *loginGuard) sweepLocked(now time.Time) {
	for ip, e := range g.limiters {
		if now.Sub(e.last) > idleWindow {
			delete(g.limiters, ip)
		}
	}
	for key, w := range g.failures {
		if now.Sub(w.since) > failureWindowD {
			delete(g.failures, key)
		}
	}
}
