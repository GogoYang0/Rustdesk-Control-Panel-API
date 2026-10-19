package limit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// LoginGuard implements the two-track protection shared by /auth/login and
// /invitations/accept:
//   - per-IP token bucket: 5 attempts per minute, then 429.
//   - per account+IP failure counter: 5 failures within 15 minutes locks that
//     pair out, without locking the account itself.
//
// Both maps are hard bounded (CWE-770):
//   - limiters are evicted least-recently-seen first once the cap is reached;
//   - failure windows are never evicted while still valid, because dropping
//     them would bypass the lockout. When the failure table is full, new pairs
//     are simply not tracked and stay subject to the per-IP bucket only.
//
// Maintenance runs at most once per second, so a burst of inserts cannot turn
// into a full-table scan on every request.
type LoginGuard struct {
	mu       sync.Mutex
	limiters map[string]*ipEntry
	failures map[string]*failureWindow
	now      func() time.Time
	lastGC   time.Time
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
	maxLimiters     = 8192
	maxFailures     = 8192
	gcInterval      = time.Second
)

func NewLoginGuard() *LoginGuard {
	return &LoginGuard{
		limiters: map[string]*ipEntry{},
		failures: map[string]*failureWindow{},
		now:      time.Now,
	}
}

// allowIP reports whether the IP may attempt another credential check.
func (g *LoginGuard) AllowIP(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	g.maybeGCLocked(now)

	entry, ok := g.limiters[ip]
	if !ok {
		if len(g.limiters) >= maxLimiters {
			g.evictLRULocked()
		}
		entry = &ipEntry{lim: rate.NewLimiter(rate.Every(time.Minute/ipRatePerMinute), ipBurst)}
		g.limiters[ip] = entry
	}
	entry.last = now
	return entry.lim.Allow()
}

// locked reports whether the account+IP pair is currently locked out.
func (g *LoginGuard) Locked(account, ip string) bool {
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
func (g *LoginGuard) RecordFailure(account, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	g.maybeGCLocked(now)

	key := account + "\x00" + ip
	w, ok := g.failures[key]
	if !ok || now.Sub(w.since) > failureWindowD {
		if len(g.failures) >= maxFailures {
			// Never evict a live window: that would reset a lockout. The pair
			// stays throttled by the per-IP bucket instead.
			return
		}
		g.failures[key] = &failureWindow{count: 1, since: now}
		return
	}
	w.count++
}

// reset clears the failure counter after a successful credential check.
func (g *LoginGuard) Reset(account, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, account+"\x00"+ip)
}

// maybeGCLocked runs idle cleanup at most once per gcInterval.
func (g *LoginGuard) maybeGCLocked(now time.Time) {
	if !g.lastGC.IsZero() && now.Sub(g.lastGC) < gcInterval {
		return
	}
	g.lastGC = now

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

// evictLRULocked drops the least recently seen limiter to make room.
func (g *LoginGuard) evictLRULocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for ip, e := range g.limiters {
		if first || e.last.Before(oldest) {
			oldestKey = ip
			oldest = e.last
			first = false
		}
	}
	if !first {
		delete(g.limiters, oldestKey)
	}
}
