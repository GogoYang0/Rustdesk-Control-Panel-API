package addressbook

import (
	"context"
	"fmt"
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

// Restoring a recycled peer grows the live list, so both the management and the
// compat restore paths must respect the per-book limit.
func TestRecycle_RestoreRespectsPeerCapacity(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}

	fill := make([]model.AddressBookPeer, 0, MaxPeersPerBook-1)
	for i := 0; i < MaxPeersPerBook-1; i++ {
		fill = append(fill, model.AddressBookPeer{
			OrganizationID: orgID, BookID: book.ID, PeerID: fmt.Sprintf("live-%d", i),
		})
	}
	require.NoError(t, store.ScopedByOrg(svc.db, orgID).CreateInBatches(&fill, 200).Error)

	recycledAt := time.Now().UTC().Add(-time.Hour)
	seedRecycled := func(peerID string) {
		t.Helper()
		require.NoError(t, store.ScopedByOrg(svc.db, orgID).Create(&model.AddressBookPeer{
			OrganizationID: orgID, BookID: book.ID, PeerID: peerID,
			DeletedAt: &recycledAt, DeletedBy: ownerID,
		}).Error)
	}

	// One slot left: restoring fills the book exactly to the limit.
	seedRecycled("recycled")
	require.NoError(t, svc.RestorePeer(ownerID, perms, orgID, book.ID, "recycled"))

	// At the limit now: a second restore is refused instead of overshooting.
	seedRecycled("recycled-2")
	require.ErrorIs(t, svc.RestorePeer(ownerID, perms, orgID, book.ID, "recycled-2"), ErrInvalidContent)
}

// The compat AddPeer path restores recycled rows in place; it must apply the
// per-book limit as well (personal books are the compat write surface).
func TestRecycle_CompatAddPeerRestoreRespectsCapacity(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.EnsurePersonalBook(ownerID, orgID)
	require.NoError(t, err)

	fill := make([]model.AddressBookPeer, 0, MaxPeersPerBook)
	for i := 0; i < MaxPeersPerBook; i++ {
		fill = append(fill, model.AddressBookPeer{
			OrganizationID: orgID, BookID: book.ID, PeerID: fmt.Sprintf("live-%d", i),
		})
	}
	require.NoError(t, store.ScopedByOrg(svc.db, orgID).CreateInBatches(&fill, 200).Error)

	recycledAt := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, store.ScopedByOrg(svc.db, orgID).Create(&model.AddressBookPeer{
		OrganizationID: orgID, BookID: book.ID, PeerID: "recycled",
		DeletedAt: &recycledAt, DeletedBy: ownerID,
	}).Error)

	require.ErrorIs(t, svc.AddPeer(ownerID, orgID, book.ID, PeerJSON{ID: "recycled"}), ErrInvalidContent)
}

// Tag rename/delete rewrites every peer of the book, including recycled rows:
// otherwise a restored peer would reference a tag that no longer exists.
func TestRecycle_TagRewriteIncludesRecycledPeers(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.EnsurePersonalBook(ownerID, orgID)
	require.NoError(t, err)

	require.NoError(t, svc.AddTag(ownerID, orgID, book.ID, "old", 0))
	require.NoError(t, svc.AddPeer(ownerID, orgID, book.ID, PeerJSON{ID: "1", Tags: []string{"old"}}))
	require.NoError(t, svc.DeletePeer(ownerID, nil, orgID, book.ID, "1"))
	require.NoError(t, svc.RenameTag(ownerID, orgID, book.ID, "old", "new"))

	var row model.AddressBookPeer
	require.NoError(t, store.WithoutTenantScope(svc.db).
		Where("book_id = ? AND peer_id = ?", book.ID, "1").First(&row).Error)
	require.NotNil(t, row.DeletedAt, "the peer stays in the recycle bin")
	require.Contains(t, row.TagsJSON, `"new"`)
	require.NotContains(t, row.TagsJSON, `"old"`)
}

// Deleting a book must remove its grants: they are keyed by book id without a
// foreign key, and a reused id would otherwise inherit stale access.
func TestGrants_DeleteBookRemovesGrants(t *testing.T) {
	svc, orgID, ownerID, memberID := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, memberID,
		model.GrantSubjectUser, model.GrantAccessRead, []string{authz.PermAddressBook})
	require.NoError(t, err)

	_, err = svc.Delete(ownerID, []string{authz.PermAddressBook}, orgID, book.ID)
	require.NoError(t, err)

	var grants int64
	require.NoError(t, store.ScopedByOrg(svc.db, orgID).
		Model(&model.AddressBookGrant{}).Where("book_id = ?", book.ID).Count(&grants).Error)
	require.Zero(t, grants, "grants must not outlive the book")
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

// A compat client that updates a peer sitting in the recycle bin must see the
// change take effect: the row is restored in place, not silently updated while
// it stays hidden from the live list the client reads back.
func TestRecycle_CompatUpdatePeerRestoresRecycledRow(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.EnsurePersonalBook(ownerID, orgID)
	require.NoError(t, err)
	_, err = svc.ReplaceBookContent(ownerID, orgID, book.ID, "", []LegacyPeer{
		{ID: "1"}, {ID: "2"},
	}, nil)
	require.NoError(t, err)
	require.NoError(t, svc.DeletePeers(ownerID, orgID, book.ID, []string{"2"}))

	require.NoError(t, svc.UpdatePeer(ownerID, orgID, book.ID, "2", map[string]any{"alias": "restored"}))
	_, peers, _, err := svc.Get(ownerID, orgID, book.ID)
	require.NoError(t, err)
	aliases := map[string]string{}
	for _, p := range peers {
		aliases[p.PeerID] = p.Alias
	}
	require.Len(t, peers, 2, "the update must restore the recycled peer")
	require.Equal(t, "restored", aliases["2"])
}
