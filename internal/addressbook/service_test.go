package addressbook

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// newServiceFixture opens an isolated in-memory database with the address
// book tables and seeds one organization and one user.
func newServiceFixture(t *testing.T) (*Service, uint, uint) {
	t.Helper()
	dsn := "file:absvc_" + sanitizeName(t.Name()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.User{}, &model.Organization{}, &model.Membership{},
		&model.AddressBook{}, &model.AddressBookPeer{}, &model.AddressBookTag{},
	))

	org := model.Organization{Name: "acme"}
	require.NoError(t, st.DB.Create(&org).Error)
	user := model.User{Email: "owner@example.com", EmailVerified: true}
	require.NoError(t, st.DB.Create(&user).Error)
	return NewService(st.DB), org.ID, user.ID
}

// sanitizeName keeps only identifier-safe characters for the sqlite DSN.
func sanitizeName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// The management API's full peer replace must preserve the compat layer's
// opaque Hash/Note fields for every peer id that survives the replace: the
// contract payload does not carry them, and dropping them would silently
// erase the client's unattended-access password hash.
func TestReplacePeers_PreservesOpaqueFields(t *testing.T) {
	svc, orgID, uid := newServiceFixture(t)

	book, err := svc.EnsurePersonalBook(uid, orgID)
	require.NoError(t, err)

	// The compat client stores the opaque fields alongside plain entries.
	require.NoError(t, svc.AddPeer(uid, orgID, book.ID, PeerJSON{
		ID: "111111111", Alias: "alpha", Hash: "client-hash", Note: "front desk",
	}))
	require.NoError(t, svc.AddPeer(uid, orgID, book.ID, PeerJSON{
		ID: "222222222", Alias: "beta",
	}))

	// The management contract replaces the list without Hash/Note and drops
	// the second peer entirely.
	beforeBook, _, _, err := svc.Get(uid, orgID, book.ID)
	require.NoError(t, err)
	fresh, err := svc.ReplacePeers(uid, nil, orgID, book.ID, []PeerInput{
		{PeerID: "111111111", Alias: "alpha-renamed"},
	})
	require.NoError(t, err)
	require.EqualValues(t, beforeBook.Revision+1, fresh.Revision,
		"the replace bumps the revision by exactly one")

	_, peers, _, err := svc.Get(uid, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.Equal(t, "111111111", peers[0].PeerID)
	require.Equal(t, "alpha-renamed", peers[0].Alias)
	require.Equal(t, "client-hash", peers[0].Hash, "the hash must survive a management replace")
	require.Equal(t, "front desk", peers[0].Note, "the note must survive a management replace")
}

// The legacy whole-book push inherits the stored Hash/Note for peers whose
// fields the payload omits (the client's _serialize never emits note), and
// an explicit value — including the empty string — replaces the stored one.
func TestReplaceBookContent_InheritsOpaqueFieldsWhenOmitted(t *testing.T) {
	svc, orgID, uid := newServiceFixture(t)

	book, err := svc.EnsurePersonalBook(uid, orgID)
	require.NoError(t, err)
	require.NoError(t, svc.AddPeer(uid, orgID, book.ID, PeerJSON{
		ID: "111111111", Alias: "alpha", Hash: "stored-hash", Note: "stored note",
	}))

	// Legacy push: peer 111 omits both optional fields; peer 222 is new with
	// an explicit empty hash (clearing semantics for a brand-new row).
	emptyHash := ""
	_, err = svc.ReplaceBookContent(uid, orgID, book.ID, "", []LegacyPeer{
		{ID: "111111111", Alias: "alpha-renamed"},
		{ID: "222222222", Alias: "beta", Hash: &emptyHash},
	}, nil)
	require.NoError(t, err)

	_, peers, _, err := svc.Get(uid, orgID, book.ID)
	require.NoError(t, err)
	byID := map[string]model.AddressBookPeer{}
	for _, p := range peers {
		byID[p.PeerID] = p
	}
	require.Len(t, byID, 2)
	require.Equal(t, "stored-hash", byID["111111111"].Hash,
		"an omitted hash must inherit the stored value")
	require.Equal(t, "stored note", byID["111111111"].Note,
		"an omitted note must inherit the stored value")
	require.Equal(t, "alpha-renamed", byID["111111111"].Alias)
	require.Empty(t, byID["222222222"].Hash, "an explicit empty value clears")
}

// The granular endpoints add one peer or tag at a time, so the collection
// limits inside normalizePeers/normalizeTags can never trigger there. Without a
// count check the book grows past the limit, and a legacy whole-book push of
// that book is rejected -- the client can no longer sync at all.
func TestGranularWrites_EnforceBookLimits(t *testing.T) {
	svc, orgID, uid := newServiceFixture(t)
	book, err := svc.EnsurePersonalBook(uid, orgID)
	require.NoError(t, err)

	peers := make([]model.AddressBookPeer, MaxPeersPerBook)
	for i := range peers {
		peers[i] = model.AddressBookPeer{
			OrganizationID: orgID, BookID: book.ID, PeerID: fmt.Sprintf("p%06d", i),
		}
	}
	require.NoError(t, store.ScopedByOrg(svc.db, orgID).CreateInBatches(&peers, 200).Error)

	require.ErrorIs(t, svc.AddPeer(uid, orgID, book.ID, PeerJSON{ID: "overflow"}), ErrInvalidContent,
		"a new peer beyond the book limit must be refused")
	require.NoError(t, svc.AddPeer(uid, orgID, book.ID, PeerJSON{ID: "p000000", Alias: "renamed"}),
		"updating an existing peer must still work at the limit")

	tags := make([]model.AddressBookTag, MaxTagsPerBook)
	for i := range tags {
		tags[i] = model.AddressBookTag{
			OrganizationID: orgID, BookID: book.ID, Name: fmt.Sprintf("tag%03d", i),
		}
	}
	require.NoError(t, store.ScopedByOrg(svc.db, orgID).CreateInBatches(&tags, 100).Error)

	require.ErrorIs(t, svc.AddTag(uid, orgID, book.ID, "overflow", 0), ErrInvalidContent,
		"a new tag beyond the book limit must be refused")
	require.NoError(t, svc.AddTag(uid, orgID, book.ID, "tag000", 16711680),
		"updating an existing tag must still work at the limit")
}
