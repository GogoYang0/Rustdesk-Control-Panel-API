package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

const (
	issuerA = "https://idp.example.com"
	issuerB = "https://idp2.example.com"
)

// seedIdentity inserts a binding directly: the binding rules themselves are
// covered by the FinishCallback tests.
func seedIdentity(t *testing.T, s *Service, userID uint, issuer, subject string) model.UserIdentity {
	t.Helper()

	row := model.UserIdentity{
		UserID:      userID,
		Provider:    model.IdentityProviderOIDC,
		Issuer:      issuer,
		Subject:     subject,
		Email:       "oidc-" + subject + "@example.com",
		LinkedAt:    time.Now(),
		LastLoginAt: nil,
	}
	if err := s.db.Create(&row).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return row
}

func TestListIdentities_ReturnsOnlyOwnRows(t *testing.T) {
	svc, _ := newFlowService(t)
	alice := seedUser(t, svc, "oidc-list-a@example.com", true)
	bob := seedUser(t, svc, "oidc-list-b@example.com", true)

	seedIdentity(t, svc, alice.ID, issuerA, "subject-a1")
	seedIdentity(t, svc, alice.ID, issuerB, "subject-a2")
	seedIdentity(t, svc, bob.ID, issuerA, "subject-b1")

	rows, err := svc.ListIdentities(context.Background(), alice.ID)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want only alice's 2", len(rows))
	}
	for _, row := range rows {
		if row.UserID != alice.ID {
			t.Fatalf("row %d belongs to %d, not %d", row.ID, row.UserID, alice.ID)
		}
	}
}

func TestUnlink_RemovesOwnIdentity(t *testing.T) {
	svc, _ := newFlowService(t)
	alice := seedUser(t, svc, "oidc-unlink@example.com", true)
	row := seedIdentity(t, svc, alice.ID, issuerA, "subject-unlink")

	if err := svc.Unlink(context.Background(), alice.ID, row.ID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	var count int64
	if err := svc.db.Model(&model.UserIdentity{}).Where("id = ?", row.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatal("the identity row survived the unlink")
	}
}

func TestUnlink_OtherUsersIdentityIs404(t *testing.T) {
	svc, _ := newFlowService(t)
	alice := seedUser(t, svc, "oidc-unlink-a@example.com", true)
	bob := seedUser(t, svc, "oidc-unlink-b@example.com", true)
	row := seedIdentity(t, svc, bob.ID, issuerA, "subject-bobs")

	if err := svc.Unlink(context.Background(), alice.ID, row.ID); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("Unlink = %v, want ErrIdentityNotFound (ownership is part of the lookup)", err)
	}
}

// TestUnlink_LastCredential pins the lockout guard: an account with no
// password, no passkeys and a single identity cannot unlink it.
func TestUnlink_LastCredential(t *testing.T) {
	svc, _ := newFlowService(t)
	alice := seedUser(t, svc, "oidc-last@example.com", true)
	row := seedIdentity(t, svc, alice.ID, issuerA, "subject-last")

	// Passwordless: RemovePassword leaves the empty-string sentinel.
	if err := svc.db.Model(&model.User{}).Where("id = ?", alice.ID).Update("password_hash", "").Error; err != nil {
		t.Fatalf("clear password: %v", err)
	}

	if err := svc.Unlink(context.Background(), alice.ID, row.ID); !errors.Is(err, ErrLastCredential) {
		t.Fatalf("Unlink = %v, want ErrLastCredential", err)
	}
	var count int64
	if err := svc.db.Model(&model.UserIdentity{}).Where("id = ?", row.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatal("the refused unlink must not delete the row")
	}
}

// TestUnlink_AllowedWithSecondCredential pins the flip side: the same
// passwordless account can unlink when a second identity remains.
func TestUnlink_AllowedWithSecondCredential(t *testing.T) {
	svc, _ := newFlowService(t)
	alice := seedUser(t, svc, "oidc-second@example.com", true)
	// Two rows for one account must differ in issuer: (user, provider, issuer)
	// is unique by design.
	first := seedIdentity(t, svc, alice.ID, issuerA, "subject-first")
	second := seedIdentity(t, svc, alice.ID, issuerB, "subject-second")

	if err := svc.db.Model(&model.User{}).Where("id = ?", alice.ID).Update("password_hash", "").Error; err != nil {
		t.Fatalf("clear password: %v", err)
	}

	if err := svc.Unlink(context.Background(), alice.ID, first.ID); err != nil {
		t.Fatalf("Unlink = %v, want success (one credential remains)", err)
	}
	var count int64
	if err := svc.db.Model(&model.UserIdentity{}).Where("user_id = ?", alice.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("remaining identities = %d, want 1", count)
	}
	_ = second
}
