package addressbook

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// RecycleBinRetention is how long a soft-deleted peer stays recoverable before
// the background sweep purges it.
const RecycleBinRetention = 30 * 24 * time.Hour

// ErrPeerNotFound reports a peer id that is not (or no longer) present in the
// requested state: live for delete, deleted for restore/purge.
var ErrPeerNotFound = errors.New("address book peer not found")

// peerWrite is the storage shape used by the full-replace paths. SetOpaque
// distinguishes the compat legacy payload (hash/note carried) from the
// management contract (hash/note preserved from the stored row).
type peerWrite struct {
	PeerID    string
	Alias     string
	Username  string
	Hostname  string
	Platform  string
	TagsJSON  string
	Hash      string
	Note      string
	SetOpaque bool
}

// replacePeersTx replaces the live peer list of a book: incoming ids are
// created or restored in place, and live peers missing from the list move to
// the recycle bin (soft delete) instead of being destroyed. Callers bump the
// revision.
func replacePeersTx(tx *gorm.DB, orgID, bookID, actorID uint, rows []peerWrite, now time.Time) error {
	var existing []model.AddressBookPeer
	if err := store.ScopedByOrg(tx, orgID).
		Where("book_id = ?", bookID).Find(&existing).Error; err != nil {
		return err
	}
	byID := make(map[string]model.AddressBookPeer, len(existing))
	for _, row := range existing {
		byID[row.PeerID] = row
	}
	incoming := make(map[string]bool, len(rows))
	for _, w := range rows {
		incoming[w.PeerID] = true
		if old, ok := byID[w.PeerID]; ok {
			updates := map[string]any{
				"alias":      w.Alias,
				"username":   w.Username,
				"hostname":   w.Hostname,
				"platform":   w.Platform,
				"tags_json":  w.TagsJSON,
				"deleted_at": nil,
				"deleted_by": uint(0),
			}
			if w.SetOpaque {
				updates["hash"] = w.Hash
				updates["note"] = w.Note
			}
			if err := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookPeer{}).
				Where("id = ?", old.ID).Updates(updates).Error; err != nil {
				return err
			}
			continue
		}
		row := model.AddressBookPeer{
			OrganizationID: orgID,
			BookID:         bookID,
			PeerID:         w.PeerID,
			Alias:          w.Alias,
			Username:       w.Username,
			Hostname:       w.Hostname,
			Platform:       w.Platform,
			TagsJSON:       w.TagsJSON,
		}
		if w.SetOpaque {
			row.Hash = w.Hash
			row.Note = w.Note
		}
		if err := store.ScopedByOrg(tx, orgID).Create(&row).Error; err != nil {
			return err
		}
	}
	for _, old := range existing {
		if old.DeletedAt != nil || incoming[old.PeerID] {
			continue
		}
		if err := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookPeer{}).
			Where("id = ?", old.ID).
			Updates(map[string]any{"deleted_at": now, "deleted_by": actorID}).Error; err != nil {
			return err
		}
	}
	return nil
}

// DeletePeer moves one live peer of a book to the recycle bin.
func (s *Service) DeletePeer(userID uint, perms []string, orgID, bookID uint, peerID string) error {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return err
	}
	access, err := s.accessFor(userID, orgID, book, perms)
	if err != nil {
		return err
	}
	if !AtLeast(access, AccessWrite) {
		return ErrForbidden
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if _, err := lockBook(tx, orgID, book.ID); err != nil {
			return err
		}
		res := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookPeer{}).
			Where("book_id = ? AND peer_id = ? AND deleted_at IS NULL", book.ID, peerID).
			Updates(map[string]any{"deleted_at": time.Now().UTC(), "deleted_by": userID})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrPeerNotFound
		}
		return bumpRevision(tx, orgID, book.ID)
	})
}

// ListRecycleBin returns the soft-deleted peers of a book, newest first.
func (s *Service) ListRecycleBin(userID uint, perms []string, orgID, bookID uint) ([]model.AddressBookPeer, error) {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return nil, err
	}
	access, err := s.accessFor(userID, orgID, book, perms)
	if err != nil {
		return nil, err
	}
	if !AtLeast(access, AccessWrite) {
		return nil, ErrForbidden
	}
	var rows []model.AddressBookPeer
	if err := store.ScopedByOrg(s.db, orgID).
		Where("book_id = ? AND deleted_at IS NOT NULL", book.ID).
		Order("deleted_at DESC").
		Order("id DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// RestorePeer returns a recycled peer to the live list.
func (s *Service) RestorePeer(userID uint, perms []string, orgID, bookID uint, peerID string) error {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return err
	}
	access, err := s.accessFor(userID, orgID, book, perms)
	if err != nil {
		return err
	}
	if !AtLeast(access, AccessWrite) {
		return ErrForbidden
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if _, err := lockBook(tx, orgID, book.ID); err != nil {
			return err
		}
		// Restoring grows the live list, so the per-book limit applies here just
		// as it does for a fresh AddPeer.
		if err := ensurePeerCapacity(tx, orgID, book.ID); err != nil {
			return err
		}
		res := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookPeer{}).
			Where("book_id = ? AND peer_id = ? AND deleted_at IS NOT NULL", book.ID, peerID).
			Updates(map[string]any{"deleted_at": nil, "deleted_by": uint(0)})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrPeerNotFound
		}
		return bumpRevision(tx, orgID, book.ID)
	})
}

// PurgePeer permanently removes a recycled peer. Purging does not change the
// live content, so the revision stays untouched.
func (s *Service) PurgePeer(userID uint, perms []string, orgID, bookID uint, peerID string) error {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return err
	}
	access, err := s.accessFor(userID, orgID, book, perms)
	if err != nil {
		return err
	}
	if !AtLeast(access, AccessFull) {
		return ErrForbidden
	}
	res := store.ScopedByOrg(s.db, orgID).
		Where("book_id = ? AND peer_id = ? AND deleted_at IS NOT NULL", book.ID, peerID).
		Delete(&model.AddressBookPeer{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrPeerNotFound
	}
	return nil
}

// SweepRecycleBin purges recycled peers older than the retention window. This
// is a cross-tenant system sweep, so it deliberately bypasses the tenant scope.
func (s *Service) SweepRecycleBin(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().Add(-RecycleBinRetention)
	res := store.WithoutTenantScope(s.db.WithContext(ctx)).
		Where("deleted_at IS NOT NULL AND deleted_at < ?", cutoff).
		Delete(&model.AddressBookPeer{})
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}
