package addressbook

import (
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
	fresh, err := svc.ReplacePeers(uid, "", orgID, book.ID, []PeerInput{
		{PeerID: "111111111", Alias: "alpha-renamed"},
	})
	require.NoError(t, err)
	require.Greater(t, fresh.Revision, book.Revision, "the replace bumps the revision")

	_, peers, _, err := svc.Get(uid, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.Equal(t, "111111111", peers[0].PeerID)
	require.Equal(t, "alpha-renamed", peers[0].Alias)
	require.Equal(t, "client-hash", peers[0].Hash, "the hash must survive a management replace")
	require.Equal(t, "front desk", peers[0].Note, "the note must survive a management replace")
}
