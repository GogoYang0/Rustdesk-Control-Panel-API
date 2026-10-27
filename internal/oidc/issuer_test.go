package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// TestStaleIssuerCount pins the O11 startup warning input: identities bound
// under a previous issuer must be counted (and warned about), never deleted and
// never treated as matching the new issuer.
func TestStaleIssuerCount(t *testing.T) {
	svc, _ := newFlowService(t)
	svc.cfg.Issuer = "https://current.example.com"

	alice := seedUser(t, svc, "oidc-stale@example.com", true)
	for _, row := range []model.UserIdentity{
		{UserID: alice.ID, Provider: model.IdentityProviderOIDC, Issuer: "https://old.example.com", Subject: "subject-old", Email: "ldap-old@example.com", LinkedAt: time.Now()},
		{UserID: alice.ID, Provider: model.IdentityProviderOIDC, Issuer: "https://current.example.com", Subject: "subject-current", Email: "ldap-current@example.com", LinkedAt: time.Now()},
	} {
		if err := svc.db.Create(&row).Error; err != nil {
			t.Fatalf("seed identity: %v", err)
		}
	}

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
