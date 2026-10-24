package addressbook

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func TestRecycle_FullReplaceMovesMissingPeersToBin(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}

	_, err = svc.ReplacePeers(ownerID, perms, orgID, book.ID, []PeerInput{
		{PeerID: "1", Alias: "one"}, {PeerID: "2", Alias: "two"},
	})
	require.NoError(t, err)
	_, live, _, err := svc.Get(ownerID, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, live, 2)
	var peerTwoID uint
	for _, p := range live {
		if p.PeerID == "2" {
			peerTwoID = p.ID
		}
	}

	_, err = svc.ReplacePeers(ownerID, perms, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.NoError(t, err)

	_, live, _, err = svc.Get(ownerID, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, live, 1)
	require.Equal(t, "1", live[0].PeerID)

	bin, err := svc.ListRecycleBin(ownerID, perms, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, bin, 1)
	require.Equal(t, "2", bin[0].PeerID)
	require.Equal(t, peerTwoID, bin[0].ID, "the recycled row keeps its identity")
	require.EqualValues(t, ownerID, bin[0].DeletedBy)
}

func TestRecycle_ReaddRestoresInPlace(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}

	_, err = svc.ReplacePeers(ownerID, perms, orgID, book.ID, []PeerInput{{PeerID: "1"}, {PeerID: "2"}})
	require.NoError(t, err)
	_, err = svc.ReplacePeers(ownerID, perms, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.NoError(t, err)
	bin, err := svc.ListRecycleBin(ownerID, perms, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, bin, 1)

	_, err = svc.ReplacePeers(ownerID, perms, orgID, book.ID, []PeerInput{{PeerID: "1"}, {PeerID: "2"}})
	require.NoError(t, err)
	_, live, _, err := svc.Get(ownerID, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, live, 2)

	bin, err = svc.ListRecycleBin(ownerID, perms, orgID, book.ID)
	require.NoError(t, err)
	require.Empty(t, bin)
}

func TestRecycle_DeleteRestorePurge(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}
	_, err = svc.ReplacePeers(ownerID, perms, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.NoError(t, err)

	require.NoError(t, svc.DeletePeer(ownerID, perms, orgID, book.ID, "1"))
	require.ErrorIs(t, svc.DeletePeer(ownerID, perms, orgID, book.ID, "1"), ErrPeerNotFound)

	bin, err := svc.ListRecycleBin(ownerID, perms, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, bin, 1)

	require.NoError(t, svc.RestorePeer(ownerID, perms, orgID, book.ID, "1"))
	require.ErrorIs(t, svc.RestorePeer(ownerID, perms, orgID, book.ID, "1"), ErrPeerNotFound)

	require.NoError(t, svc.DeletePeer(ownerID, perms, orgID, book.ID, "1"))
	require.NoError(t, svc.PurgePeer(ownerID, perms, orgID, book.ID, "1"))
	require.ErrorIs(t, svc.PurgePeer(ownerID, perms, orgID, book.ID, "1"), ErrPeerNotFound)
	bin, err = svc.ListRecycleBin(ownerID, perms, orgID, book.ID)
	require.NoError(t, err)
	require.Empty(t, bin)
}

func TestRecycle_WriteGrantCanDeleteButNotPurge(t *testing.T) {
	svc, orgID, ownerID, memberID := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}
	_, err = svc.ReplacePeers(ownerID, perms, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.NoError(t, err)
	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, memberID, model.GrantSubjectUser, model.GrantAccessWrite, perms)
	require.NoError(t, err)

	require.NoError(t, svc.DeletePeer(memberID, nil, orgID, book.ID, "1"))
	require.NoError(t, svc.RestorePeer(memberID, nil, orgID, book.ID, "1"))
	require.NoError(t, svc.DeletePeer(memberID, nil, orgID, book.ID, "1"))
	require.ErrorIs(t, svc.PurgePeer(memberID, nil, orgID, book.ID, "1"), ErrForbidden)

	// Without any grant the member cannot even delete.
	require.ErrorIs(t, svc.RestorePeer(8+1, nil, orgID, book.ID, "1"), ErrForbidden)
}

func TestRecycle_CompatReplaceSoftDeletesAndSweep(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.EnsurePersonalBook(ownerID, orgID)
	require.NoError(t, err)

	hash := "client-hash"
	_, err = svc.ReplaceBookContent(ownerID, orgID, book.ID, "", []LegacyPeer{
		{ID: "1", Alias: "one", Hash: &hash},
		{ID: "2", Alias: "two"},
	}, nil)
	require.NoError(t, err)
	_, err = svc.ReplaceBookContent(ownerID, orgID, book.ID, "", []LegacyPeer{
		{ID: "1", Alias: "one"},
	}, nil)
	require.NoError(t, err)

	_, peers, _, err := svc.Get(ownerID, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.Equal(t, "1", peers[0].PeerID)
	require.Equal(t, hash, peers[0].Hash, "surviving peers keep their opaque hash")

	bin, err := svc.ListRecycleBin(ownerID, nil, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, bin, 1, "the peer missing from the compat push is recycled, not destroyed")
	require.Equal(t, "2", bin[0].PeerID)

	// Age one entry past the retention window; only that one is purged.
	require.NoError(t, store.WithoutTenantScope(svc.db).Model(&model.AddressBookPeer{}).
		Where("book_id = ? AND peer_id = ?", book.ID, "2").
		Update("deleted_at", time.Now().UTC().Add(-RecycleBinRetention-time.Hour)).Error)

	swept, err := svc.SweepRecycleBin(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, swept)
	bin, err = svc.ListRecycleBin(ownerID, nil, orgID, book.ID)
	require.NoError(t, err)
	require.Empty(t, bin)
}

func TestRecycle_CompatDeletePeersSoftDeletes(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.EnsurePersonalBook(ownerID, orgID)
	require.NoError(t, err)
	hash := "h"
	_, err = svc.ReplaceBookContent(ownerID, orgID, book.ID, "", []LegacyPeer{
		{ID: "1", Hash: &hash}, {ID: "2"},
	}, nil)
	require.NoError(t, err)

	require.NoError(t, svc.DeletePeers(ownerID, orgID, book.ID, []string{"2"}))
	bin, err := svc.ListRecycleBin(ownerID, nil, orgID, book.ID)
	require.NoError(t, err)
	require.Len(t, bin, 1)
	require.Equal(t, "2", bin[0].PeerID)
}
