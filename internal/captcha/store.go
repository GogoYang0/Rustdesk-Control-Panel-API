package captcha

import (
	"sync"
	"time"
)

// usedStore remembers consumed challenge signatures so a payload cannot be
// replayed. It is process-local on purpose: the challenge state itself is
// stateless, and the login rate limiter already has the same lifetime.
type usedStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
	max     int
	now     func() time.Time
}

// newUsedStore bounds the table; oldest entries are evicted at capacity.
func newUsedStore(max int, now func() time.Time) *usedStore {
	return &usedStore{entries: map[string]time.Time{}, max: max, now: nowOrDefault(now)}
}

// Reserve marks key as used until ttl elapses and reports whether it was free.
// A key is reserved before its proof is verified: a challenge gets exactly one
// attempt, so a wrong solution is not a free retry.
func (u *usedStore) Reserve(key string, ttl time.Duration) bool {
	if key == "" {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	now := u.now()
	if expires, ok := u.entries[key]; ok && now.Before(expires) {
		return false
	}
	if len(u.entries) >= u.max {
		u.evictLocked(now)
	}
	u.entries[key] = now.Add(ttl)
	return true
}

// evictLocked drops expired entries first, then the entry expiring soonest.
func (u *usedStore) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	first := true
	for key, expires := range u.entries {
		if !now.Before(expires) {
			delete(u.entries, key)
			continue
		}
		if first || expires.Before(oldest) {
			oldestKey, oldest, first = key, expires, false
		}
	}
	if len(u.entries) >= u.max && !first {
		delete(u.entries, oldestKey)
	}
}
