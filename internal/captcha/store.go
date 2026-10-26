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
	nextGen uint64
}

// usedEntry is one reservation. verified marks a proof that passed: it must
// survive until its TTL expires, while a reservation that never passed may be
// dropped under capacity pressure without weakening the single-use guarantee.
type usedEntry struct {
	expires  time.Time
	verified bool
	gen      uint64
}

// Reservation is the handle of one successful Reserve call. Verification and
// release address the exact entry they were created for, so a reservation that
// was evicted mid-flight can neither promote nor drop a newer one for the same
// key.
type Reservation struct {
	key string
	gen uint64
	ttl time.Duration
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
func (u *usedStore) Reserve(key string, ttl time.Duration) (Reservation, bool) {
	if key == "" {
		return Reservation{}, false
	}
	key = digestKey(key)

	u.mu.Lock()
	defer u.mu.Unlock()

	now := u.now()
	if entry, ok := u.entries[key]; ok && now.Before(entry.expires) {
		return Reservation{}, false
	}
	if len(u.entries) >= u.max && !u.makeRoomLocked(now) {
		// Every unexpired entry is a proof that already passed: admitting a new
		// reservation would have to drop one and re-open it for replay.
		return Reservation{}, false
	}
	u.nextGen++
	res := Reservation{key: key, gen: u.nextGen, ttl: ttl}
	u.entries[key] = usedEntry{expires: now.Add(ttl), gen: res.gen}
	return res, true
}

// MarkVerified promotes this reservation to a passed proof, which then keeps
// its slot until expiry even when the table is under pressure. When the entry
// was evicted while the provider call was in flight, the verdict is recorded
// anyway - a slow success must not leave the proof replayable - unless a newer
// reservation already owns the key.
func (u *usedStore) MarkVerified(res Reservation) {
	if res.key == "" {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if entry, ok := u.entries[res.key]; ok {
		if entry.gen != res.gen {
			// A newer reservation owns the key; the stale verdict must not
			// promote it.
			return
		}
		entry.verified = true
		u.entries[res.key] = entry
		return
	}
	// The reservation was evicted and nobody took the key since, so record the
	// passed proof with the caller's TTL. It is created verified, which means
	// capacity pressure may free other pending slots but never this one.
	now := u.now()
	if len(u.entries) >= u.max && !u.makeRoomLocked(now) {
		// The table is full of passed proofs; there is no slot to hold this
		// verdict. Losing it is the least bad outcome: dropping another passed
		// proof would make that one replayable instead.
		return
	}
	u.entries[res.key] = usedEntry{expires: now.Add(res.ttl), verified: true, gen: res.gen}
}

// Release frees this reservation after a call that produced no verdict
// (transport fault or provider error), so an outage does not burn the client's
// challenge. Releasing is safe for replay protection: the token never passed,
// so a later attempt is still the first successful local use. A stale handle
// leaves a newer reservation untouched.
func (u *usedStore) Release(res Reservation) {
	if res.key == "" {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	entry, ok := u.entries[res.key]
	if !ok || entry.gen != res.gen {
		return
	}
	delete(u.entries, res.key)
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
