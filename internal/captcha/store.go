package captcha

import (
	"crypto/sha256"
	"sync"
	"time"
)

// usedStore remembers consumed challenge signatures so a payload cannot be
// replayed. It is process-local on purpose: the challenge state itself is
// stateless, and the login rate limiter already has the same lifetime.
type usedStore struct {
	mu      sync.Mutex
	entries map[string]usedEntry
	max     int
	now     func() time.Time
}

// usedEntry is one reservation. verified marks a proof that passed: it must
// survive until its TTL expires, while a reservation that never passed may be
// dropped under capacity pressure without weakening the single-use guarantee.
type usedEntry struct {
	expires  time.Time
	verified bool
}

// newUsedStore bounds the table; see makeRoomLocked for the eviction policy.
func newUsedStore(max int, now func() time.Time) *usedStore {
	return &usedStore{entries: map[string]usedEntry{}, max: max, now: nowOrDefault(now)}
}

// digestKey collapses the caller-supplied string to a fixed size, so retention
// is bounded by the table size instead of by the submitted token length.
func digestKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return string(sum[:])
}

// Reserve marks key as used until ttl elapses and reports whether it was free.
// A key is reserved before its proof is verified: a challenge gets exactly one
// attempt, so a wrong solution is not a free retry.
func (u *usedStore) Reserve(key string, ttl time.Duration) bool {
	if key == "" {
		return false
	}
	key = digestKey(key)

	u.mu.Lock()
	defer u.mu.Unlock()

	now := u.now()
	if entry, ok := u.entries[key]; ok && now.Before(entry.expires) {
		return false
	}
	if len(u.entries) >= u.max && !u.makeRoomLocked(now) {
		// Every unexpired entry is a proof that already passed: admitting a new
		// reservation would have to drop one and re-open it for replay.
		return false
	}
	u.entries[key] = usedEntry{expires: now.Add(ttl)}
	return true
}

// MarkVerified promotes a reservation to a passed proof, which then keeps its
// slot until expiry even when the table is under pressure.
func (u *usedStore) MarkVerified(key string) {
	key = digestKey(key)

	u.mu.Lock()
	defer u.mu.Unlock()

	entry, ok := u.entries[key]
	if !ok {
		return
	}
	entry.verified = true
	u.entries[key] = entry
}

// Release frees a reservation whose verification never produced a verdict
// (transport fault or provider error), so an outage does not burn the client's
// challenge. Releasing is safe for replay protection: the token never passed,
// so a later attempt is still the first successful local use.
func (u *usedStore) Release(key string) {
	key = digestKey(key)

	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.entries, key)
}

// makeRoomLocked drops expired entries and then the pending reservation that
// expires soonest, and reports whether a slot is free. Passed proofs are never
// evicted: dropping one would let an already consumed proof through again.
func (u *usedStore) makeRoomLocked(now time.Time) bool {
	var pendingKey string
	var pendingExpires time.Time
	first := true
	for key, entry := range u.entries {
		if !now.Before(entry.expires) {
			delete(u.entries, key)
			continue
		}
		if entry.verified {
			continue
		}
		if first || entry.expires.Before(pendingExpires) {
			pendingKey, pendingExpires, first = key, entry.expires, false
		}
	}
	if len(u.entries) < u.max {
		return true
	}
	if first {
		return false
	}
	delete(u.entries, pendingKey)
	return true
}
