package oidc

import (
	"context"
	"testing"
)

// TestStaleIssuerCount pins the O11 startup warning input: identities bound
// under a previous issuer must be counted (and warned about), never deleted and
// never treated as matching the new issuer.
func TestStaleIssuerCount(t *testing.T) {
	svc, _ := newFlowService(t)
	svc.cfg.Issuer = "https://current.example.com"

	alice := seedUser(t, svc, "oidc-stale@example.com", true)
	seedIdentity(t, svc, alice.ID, "https://old.example.com", "subject-old")
	seedIdentity(t, svc, alice.ID, "https://current.example.com", "subject-current")

	got, err := svc.StaleIssuerCount(context.Background())
	if err != nil {
		t.Fatalf("StaleIssuerCount: %v", err)
	}
	if got != 1 {
		t.Fatalf("stale = %d, want 1 (only the old-issuer row)", got)
	}

	// Point the config at the old issuer: the warning must flip sides, proving
	// the count compares against the configured issuer, not a fixed one.
	svc.cfg.Issuer = "https://old.example.com"
	got, err = svc.StaleIssuerCount(context.Background())
	if err != nil {
		t.Fatalf("StaleIssuerCount: %v", err)
	}
	if got != 1 {
		t.Fatalf("stale after switch = %d, want 1", got)
	}
}
