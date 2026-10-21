// Granular operations used by the client compat layer (task 9): the RustDesk
// client mutates one peer/tag at a time inside its personal book. Every
// mutation runs in a transaction holding the book row lock and bumps the
// revision, mirroring ReplacePeers/ReplaceTags.
package addressbook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// PersonalBookName is the reserved name of the per-user personal book the
// compat layer binds to; the admin API surface shares the same book, so the
// client and the panel see one address book per user.
const PersonalBookName = "Personal"

// EnsurePersonalBook returns the user's personal book in the organization,
// creating it on first use. The duplicate-name race with a concurrent first
// login resolves by re-reading: the unique pre-check inside Create plus the
// (scope, owner, name) pre-check make at most one row exist.
func (s *Service) EnsurePersonalBook(userID, orgID uint) (*model.AddressBook, error) {
	var book model.AddressBook
	err := store.ScopedByOrg(s.db, orgID).
		Where("scope = ? AND owner_id = ? AND name = ?",
			model.AddressBookScopePersonal, userID, PersonalBookName).
		First(&book).Error
	if err == nil {
		return &book, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	created, err := s.Create(userID, orgID, model.AddressBookScopePersonal, PersonalBookName)
	if errors.Is(err, ErrDuplicateName) {
		// A concurrent first login created it; read the winner.
		err = store.ScopedByOrg(s.db, orgID).
			Where("scope = ? AND owner_id = ? AND name = ?",
				model.AddressBookScopePersonal, userID, PersonalBookName).
			First(&book).Error
		if err != nil {
			return nil, err
		}
		return &book, nil
	}
	if err != nil {
		return nil, err
	}
	return created, nil
}

// PeerJSON is one entry of the client's peer list (rustdesk
// Peer.toCustomJson plus the note field the update endpoint accepts); it is
// the wire shape shared by the legacy whole-book payload and the granular
// paged fetch.
type PeerJSON struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Hostname string   `json:"hostname"`
	Platform string   `json:"platform"`
	Alias    string   `json:"alias"`
	Tags     []string `json:"tags"`
	Hash     string   `json:"hash,omitempty"`
	Note     string   `json:"note,omitempty"`
}

// peerToJSON maps a stored row onto the client wire shape.
func peerToJSON(p model.AddressBookPeer) PeerJSON {
	tags, err := DecodeTagsJSON(p.TagsJSON)
	if err != nil {
		tags = []string{}
	}
	return PeerJSON{
		ID:       p.PeerID,
		Username: p.Username,
		Hostname: p.Hostname,
		Platform: p.Platform,
		Alias:    p.Alias,
		Tags:     tags,
		Hash:     p.Hash,
		Note:     p.Note,
	}
}

// BookSnapshot is the full content of one book for the compat layer.
type BookSnapshot struct {
	Book  *model.AddressBook
	Peers []PeerJSON
	Tags  []model.AddressBookTag
}

// SnapshotForCompat loads book, peers and tags and maps the peers onto the
// client wire shape.
func (s *Service) SnapshotForCompat(userID, orgID, bookID uint) (*BookSnapshot, error) {
	book, peers, tags, err := s.Get(userID, orgID, bookID)
	if err != nil {
		return nil, err
	}
	out := make([]PeerJSON, 0, len(peers))
	for _, p := range peers {
		out = append(out, peerToJSON(p))
	}
	return &BookSnapshot{Book: book, Peers: out, Tags: tags}, nil
}

// SnapshotForCompatPersonal loads the user's personal book content for the
// legacy whole-book endpoints; nil book means the user has none yet (the
// legacy GET answers null and the push creates it).
func (s *Service) SnapshotForCompatPersonal(userID, orgID uint) (*BookSnapshot, error) {
	var book model.AddressBook
	err := store.ScopedByOrg(s.db, orgID).
		Where("scope = ? AND owner_id = ? AND name = ?",
			model.AddressBookScopePersonal, userID, PersonalBookName).
		First(&book).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.SnapshotForCompat(userID, orgID, book.ID)
}

// LegacyPeer is one peer entry of the legacy /api/ab payload. Hash and Note
// are pointers so "omitted" and "explicitly empty" stay distinguishable: an
// omitted field inherits the stored value (the client's _serialize never
// emits note, and older clients may omit hash), while an explicit empty
// string clears it.
type LegacyPeer struct {
	ID       string
	Username string
	Hostname string
	Platform string
	Alias    string
	Tags     []string
	Hash     *string
	Note     *string
}

// LegacyContent is the decoded legacy /api/ab data payload: tag_colors is a
// JSON-encoded STRING of {tag: color} (the client jsonEncodes the map before
// embedding it), which DecodeLegacyContent resolves into Colors.
type LegacyContent struct {
	Tags      []string
	Peers     []LegacyPeer
	TagColors string
	Colors    map[string]uint32
}

// legacyPeerRaw mirrors the wire shape with optional fields as pointers.
type legacyPeerRaw struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Hostname string   `json:"hostname"`
	Platform string   `json:"platform"`
	Alias    string   `json:"alias"`
	Tags     []string `json:"tags"`
	Hash     *string  `json:"hash"`
	Note     *string  `json:"note"`
}

// DecodeLegacyContent parses the client's serialized book payload.
func DecodeLegacyContent(raw string) (*LegacyContent, error) {
	var rawContent struct {
		Tags      []string        `json:"tags"`
		Peers     []legacyPeerRaw `json:"peers"`
		TagColors string          `json:"tag_colors"`
	}
	if err := json.Unmarshal([]byte(raw), &rawContent); err != nil {
		return nil, fmt.Errorf("decode legacy address book data: %w", err)
	}
	content := &LegacyContent{
		Tags:      rawContent.Tags,
		TagColors: rawContent.TagColors,
		Colors:    map[string]uint32{},
	}
	if content.Tags == nil {
		content.Tags = []string{}
	}
	content.Peers = make([]LegacyPeer, 0, len(rawContent.Peers))
	for _, p := range rawContent.Peers {
		tags := p.Tags
		if tags == nil {
			tags = []string{}
		}
		content.Peers = append(content.Peers, LegacyPeer{
			ID: p.ID, Username: p.Username, Hostname: p.Hostname,
			Platform: p.Platform, Alias: p.Alias, Tags: tags,
			Hash: p.Hash, Note: p.Note,
		})
	}
	if content.TagColors != "" && content.TagColors != "null" {
		var colors map[string]uint32
		if err := json.Unmarshal([]byte(content.TagColors), &colors); err != nil {
			return nil, fmt.Errorf("decode legacy tag colors: %w", err)
		}
		content.Colors = colors
	}
	return content, nil
}

// EncodeLegacyContent serialises the snapshot back into the client's payload
// string ({"tags", "peers", "tag_colors"} with tag_colors embedded as a
// JSON string, exactly like the client's _serialize).
func EncodeLegacyContent(snap *BookSnapshot) string {
	tagNames := make([]string, 0, len(snap.Tags))
	colors := map[string]uint32{}
	for _, t := range snap.Tags {
		tagNames = append(tagNames, t.Name)
		colors[t.Name] = t.Color
	}
	colorsJSON, err := json.Marshal(colors)
	if err != nil {
		colorsJSON = []byte("{}")
	}
	peers := snap.Peers
	if peers == nil {
		peers = []PeerJSON{}
	}
	b, err := json.Marshal(map[string]any{
		"tags":       tagNames,
		"peers":      peers,
		"tag_colors": string(colorsJSON),
	})
	if err != nil {
		return "{\"tags\":[],\"peers\":[],\"tag_colors\":\"{}\"}"
	}
	return string(b)
}

// ContentHash derives the deterministic content hash used for conflict
// detection on the legacy push path: Go's json.Marshal orders map keys, and
// the snapshot's slices come back in stable order (peers by id, tags by
// name), so equal contents hash equally.
func ContentHash(snap *BookSnapshot) string {
	colors := map[string]uint32{}
	for _, t := range snap.Tags {
		colors[t.Name] = t.Color
	}
	peers := snap.Peers
	if peers == nil {
		peers = []PeerJSON{}
	}
	b, err := json.Marshal(map[string]any{
		"tags":       tagNamesOf(snap.Tags),
		"peers":      peers,
		"tag_colors": colors,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// tagNamesOf extracts the tag names in stored order.
func tagNamesOf(tags []model.AddressBookTag) []string {
	names := make([]string, 0, len(tags))
	for _, t := range tags {
		names = append(names, t.Name)
	}
	return names
}

// AddPeer upserts one peer entry: an existing peer id merges the provided
// fields, a new one is created. Revision bumps once per call.
func (s *Service) AddPeer(userID uint, orgID, bookID uint, in PeerJSON) error {
	if _, err := normalizePeers([]LegacyPeer{{
		ID: in.ID, Username: in.Username, Hostname: in.Hostname,
		Platform: in.Platform, Alias: in.Alias, Tags: in.Tags,
		Hash: &in.Hash, Note: &in.Note,
	}}); err != nil {
		return err
	}
	return s.mutateBook(userID, orgID, bookID, func(tx *gorm.DB, book *model.AddressBook) error {
		var row model.AddressBookPeer
		err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ? AND peer_id = ?", book.ID, in.ID).First(&row).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if err := ensurePeerCapacity(tx, orgID, book.ID); err != nil {
				return err
			}
			row = model.AddressBookPeer{
				OrganizationID: orgID,
				BookID:         book.ID,
				PeerID:         in.ID,
				Alias:          in.Alias,
				Username:       in.Username,
				Hostname:       in.Hostname,
				Platform:       in.Platform,
				TagsJSON:       TagsJSON(in.Tags),
				Hash:           in.Hash,
				Note:           in.Note,
			}
			return store.ScopedByOrg(tx, orgID).Create(&row).Error
		case err != nil:
			return err
		}
		// Merge: the client keeps its own copy; empty fields never erase
		// stored values (partial payloads from older clients).
		updates := map[string]any{}
		if in.Alias != "" {
			updates["alias"] = in.Alias
		}
		if in.Username != "" {
			updates["username"] = in.Username
		}
		if in.Hostname != "" {
			updates["hostname"] = in.Hostname
		}
		if in.Platform != "" {
			updates["platform"] = in.Platform
		}
		if in.Hash != "" {
			updates["hash"] = in.Hash
		}
		if in.Note != "" {
			updates["note"] = in.Note
		}
		if in.Tags != nil {
			updates["tags_json"] = TagsJSON(in.Tags)
		}
		if len(updates) == 0 {
			return nil
		}
		return store.ScopedByOrg(tx, orgID).Model(&row).Updates(updates).Error
	})
}

// UpdatePeer applies a partial update ({"id": ..., field: value}) to one
// peer: only present fields are touched.
func (s *Service) UpdatePeer(userID uint, orgID, bookID uint, peerID string, fields map[string]any) error {
	return s.mutateBook(userID, orgID, bookID, func(tx *gorm.DB, book *model.AddressBook) error {
		var row model.AddressBookPeer
		err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ? AND peer_id = ?", book.ID, peerID).First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrBookNotFound
		}
		if err != nil {
			return err
		}
		updates := map[string]any{}
		for _, key := range []string{"alias", "username", "hostname", "platform", "hash", "note"} {
			if v, ok := fields[key]; ok {
				if str, isStr := v.(string); isStr {
					updates[key] = str
				}
			}
		}
		if raw, ok := fields["tags"]; ok {
			var tags []string
			b, merr := json.Marshal(raw)
			if merr == nil && json.Unmarshal(b, &tags) == nil {
				updates["tags_json"] = TagsJSON(tags)
			}
		}
		if len(updates) == 0 {
			return nil
		}
		return store.ScopedByOrg(tx, orgID).Model(&row).Updates(updates).Error
	})
}

// DeletePeers removes the listed peer ids from the book.
func (s *Service) DeletePeers(userID uint, orgID, bookID uint, peerIDs []string) error {
	return s.mutateBook(userID, orgID, bookID, func(tx *gorm.DB, book *model.AddressBook) error {
		return store.ScopedByOrg(tx, orgID).
			Where("book_id = ? AND peer_id IN ?", book.ID, peerIDs).
			Delete(&model.AddressBookPeer{}).Error
	})
}

// AddTag creates a tag or refreshes its color when the name already exists
// (the client pre-checks duplicates; idempotent behaviour avoids error
// loops across concurrent clients).
func (s *Service) AddTag(userID uint, orgID, bookID uint, name string, color uint32) error {
	if _, err := normalizeTags([]TagInput{{Name: name, Color: color}}); err != nil {
		return err
	}
	return s.mutateBook(userID, orgID, bookID, func(tx *gorm.DB, book *model.AddressBook) error {
		var row model.AddressBookTag
		err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ? AND name = ?", book.ID, name).First(&row).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if err := ensureTagCapacity(tx, orgID, book.ID); err != nil {
				return err
			}
			row = model.AddressBookTag{
				OrganizationID: orgID,
				BookID:         book.ID,
				Name:           name,
				Color:          color,
			}
			return store.ScopedByOrg(tx, orgID).Create(&row).Error
		case err != nil:
			return err
		}
		if row.Color == color {
			return nil
		}
		return store.ScopedByOrg(tx, orgID).Model(&row).
			Update("color", color).Error
	})
}

// RenameTag renames a tag and rewrites every peer's tag list that referenced
// the old name, in one transaction.
func (s *Service) RenameTag(userID uint, orgID, bookID uint, oldName, newName string) error {
	return s.mutateBook(userID, orgID, bookID, func(tx *gorm.DB, book *model.AddressBook) error {
		var row model.AddressBookTag
		err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ? AND name = ?", book.ID, oldName).First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrBookNotFound
		}
		if err != nil {
			return err
		}
		if oldName == newName {
			// A client retrying a rename it already performed must succeed.
			return nil
		}
		if _, err := normalizeTags([]TagInput{{Name: newName}}); err != nil {
			return err
		}
		// Renaming onto an existing name would hit the unique index and
		// answer 500; report it as invalid content instead.
		var clash model.AddressBookTag
		err = store.ScopedByOrg(tx, orgID).
			Where("book_id = ? AND name = ?", book.ID, newName).First(&clash).Error
		switch {
		case err == nil:
			return fmt.Errorf("%w: tag name already exists", ErrInvalidContent)
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return err
		}
		if err := store.ScopedByOrg(tx, orgID).Model(&row).
			Update("name", newName).Error; err != nil {
			return err
		}
		return rewritePeerTags(tx, orgID, book.ID, func(tags []string) []string {
			out := make([]string, 0, len(tags))
			for _, t := range tags {
				if t == oldName {
					out = append(out, newName)
				} else {
					out = append(out, t)
				}
			}
			return out
		})
	})
}

// UpdateTagColor changes a tag's color.
func (s *Service) UpdateTagColor(userID uint, orgID, bookID uint, name string, color uint32) error {
	return s.mutateBook(userID, orgID, bookID, func(tx *gorm.DB, book *model.AddressBook) error {
		res := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookTag{}).
			Where("book_id = ? AND name = ?", book.ID, name).
			Update("color", color)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrBookNotFound
		}
		return nil
	})
}

// DeleteTag removes a tag and drops it from every peer's tag list, in one
// transaction.
func (s *Service) DeleteTag(userID uint, orgID, bookID uint, name string) error {
	return s.mutateBook(userID, orgID, bookID, func(tx *gorm.DB, book *model.AddressBook) error {
		res := store.ScopedByOrg(tx, orgID).
			Where("book_id = ? AND name = ?", book.ID, name).
			Delete(&model.AddressBookTag{})
		if res.Error != nil {
			return res.Error
		}
		return rewritePeerTags(tx, orgID, book.ID, func(tags []string) []string {
			out := make([]string, 0, len(tags))
			for _, t := range tags {
				if t != name {
					out = append(out, t)
				}
			}
			return out
		})
	})
}

// ErrInvalidContent reports address book content that violates a column bound or
// a uniqueness rule. The API layer maps it to 400 instead of letting the
// database answer with 500.
var ErrInvalidContent = errors.New("address book content is invalid")

// Content limits shared by the management API and the client compat path: both
// write the same rows, so a value accepted by one must be accepted by the other.
const (
	// MaxPeersPerBook and MaxTagsPerBook bound one whole-book write.
	MaxPeersPerBook = 2000
	MaxTagsPerBook  = 256
	// MaxTagsPerPeer bounds the tag list carried by a single peer.
	MaxTagsPerPeer = 64

	maxPeerIDRunes   = 64
	maxPeerTextRunes = 128
	maxPlatformRunes = 64
	maxTagsJSONRunes = 2048
	maxPeerHashRunes = 128
	maxPeerNoteRunes = 512
	maxTagNameRunes  = 64
)

// validatePeerContent checks one peer against the column bounds. Lengths are
// counted in runes, matching the management API: the columns hold characters,
// not bytes, so a multi-byte tag list must not be rejected on one path only.
func validatePeerContent(id, alias, username, hostname, platform string, tags []string, hash, note string) error {
	if id == "" || utf8.RuneCountInString(id) > maxPeerIDRunes {
		return fmt.Errorf("%w: peer id", ErrInvalidContent)
	}
	if utf8.RuneCountInString(alias) > maxPeerTextRunes ||
		utf8.RuneCountInString(username) > maxPeerTextRunes ||
		utf8.RuneCountInString(hostname) > maxPeerTextRunes ||
		utf8.RuneCountInString(platform) > maxPlatformRunes {
		return fmt.Errorf("%w: peer fields", ErrInvalidContent)
	}
	if utf8.RuneCountInString(TagsJSON(tags)) > maxTagsJSONRunes {
		return fmt.Errorf("%w: peer tags", ErrInvalidContent)
	}
	if len(tags) > MaxTagsPerPeer {
		return fmt.Errorf("%w: too many tags on one peer", ErrInvalidContent)
	}
	if utf8.RuneCountInString(hash) > maxPeerHashRunes ||
		utf8.RuneCountInString(note) > maxPeerNoteRunes {
		return fmt.Errorf("%w: peer hash or note", ErrInvalidContent)
	}
	return nil
}

// normalizePeers deduplicates by id (the last occurrence wins, matching the
// legacy whole-book semantics) and validates the column bounds and the per-book
// limit, so a client push can never reach the unique index, an over-long column
// or a collection the management API would reject.
func normalizePeers(peers []LegacyPeer) ([]LegacyPeer, error) {
	out := make([]LegacyPeer, 0, len(peers))
	index := make(map[string]int, len(peers))
	for _, p := range peers {
		if err := validatePeerContent(p.ID, p.Alias, p.Username, p.Hostname, p.Platform,
			p.Tags, derefString(p.Hash), derefString(p.Note)); err != nil {
			return nil, err
		}
		if at, seen := index[p.ID]; seen {
			out[at] = p
			continue
		}
		index[p.ID] = len(out)
		out = append(out, p)
	}
	if len(out) > MaxPeersPerBook {
		return nil, fmt.Errorf("%w: too many peers", ErrInvalidContent)
	}
	return out, nil
}

// normalizeTags deduplicates by name, validates the name bound and enforces the
// per-book limit.
func normalizeTags(tags []TagInput) ([]TagInput, error) {
	out := make([]TagInput, 0, len(tags))
	index := make(map[string]int, len(tags))
	for _, tg := range tags {
		if tg.Name == "" || utf8.RuneCountInString(tg.Name) > maxTagNameRunes {
			return nil, fmt.Errorf("%w: tag name", ErrInvalidContent)
		}
		if at, seen := index[tg.Name]; seen {
			out[at] = tg
			continue
		}
		index[tg.Name] = len(out)
		out = append(out, tg)
	}
	if len(out) > MaxTagsPerBook {
		return nil, fmt.Errorf("%w: too many tags", ErrInvalidContent)
	}
	return out, nil
}

// derefString resolves an optional string field, treating nil as absent.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ensurePeerCapacity enforces the per-book peer limit for granular writes. The
// whole-book path checks it after normalisation, but AddPeer hands
// normalizePeers a single element, so that check can never trip there.
func ensurePeerCapacity(tx *gorm.DB, orgID, bookID uint) error {
	var n int64
	if err := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookPeer{}).
		Where("book_id = ?", bookID).Count(&n).Error; err != nil {
		return err
	}
	if n >= MaxPeersPerBook {
		return fmt.Errorf("%w: too many peers", ErrInvalidContent)
	}
	return nil
}

// ensureTagCapacity mirrors ensurePeerCapacity for tags.
func ensureTagCapacity(tx *gorm.DB, orgID, bookID uint) error {
	var n int64
	if err := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookTag{}).
		Where("book_id = ?", bookID).Count(&n).Error; err != nil {
		return err
	}
	if n >= MaxTagsPerBook {
		return fmt.Errorf("%w: too many tags", ErrInvalidContent)
	}
	return nil
}

// ReplaceBookContent swaps peers and tags in one transaction (legacy /api/ab
// POST semantics) and bumps the revision once. Peers use the legacy wire
// shape with optional Hash/Note: an omitted field inherits the stored value
// (the client's _serialize never emits note, and older clients may omit
// hash), while an explicit empty string clears it. When expectedHash is
// non-empty it is compared against the content hash recomputed under the
// book row lock — the optimistic-concurrency check runs inside the same
// transaction as the replace, so a stale push cannot slip through a
// check-then-replace race.
func (s *Service) ReplaceBookContent(userID uint, orgID, bookID uint, expectedHash string, peers []LegacyPeer, tags []TagInput) (*model.AddressBook, error) {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return nil, err
	}
	if !canWrite(book, userID, "") {
		return nil, ErrForbidden
	}
	// Client pushes are untrusted input: apply the same column bounds and
	// uniqueness rules as the management API, deduplicating rather than
	// failing the whole push on a repeated id or tag name.
	peers, err = normalizePeers(peers)
	if err != nil {
		return nil, err
	}
	tags, err = normalizeTags(tags)
	if err != nil {
		return nil, err
	}

	var fresh model.AddressBook
	err = s.db.Transaction(func(tx *gorm.DB) error {
		current, err := lockBook(tx, orgID, book.ID)
		if err != nil {
			return err
		}
		if expectedHash != "" {
			snap, err := s.snapshotTx(tx, orgID, current)
			if err != nil {
				return err
			}
			if ContentHash(snap) != expectedHash {
				return ErrContentConflict
			}
		}
		// Load the stored opaque fields before the delete: omitted legacy
		// fields inherit them, explicit empty strings clear them.
		var stored []model.AddressBookPeer
		if err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ?", book.ID).Find(&stored).Error; err != nil {
			return err
		}
		opaque := make(map[string]model.AddressBookPeer, len(stored))
		for _, row := range stored {
			opaque[row.PeerID] = row
		}
		if err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ?", book.ID).Delete(&model.AddressBookPeer{}).Error; err != nil {
			return err
		}
		if err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ?", book.ID).Delete(&model.AddressBookTag{}).Error; err != nil {
			return err
		}
		for _, p := range peers {
			row := model.AddressBookPeer{
				OrganizationID: orgID,
				BookID:         book.ID,
				PeerID:         p.ID,
				Alias:          p.Alias,
				Username:       p.Username,
				Hostname:       p.Hostname,
				Platform:       p.Platform,
				TagsJSON:       TagsJSON(p.Tags),
			}
			if old, ok := opaque[p.ID]; ok {
				row.Hash = resolveOptional(p.Hash, old.Hash)
				row.Note = resolveOptional(p.Note, old.Note)
			} else {
				row.Hash = resolveOptional(p.Hash, "")
				row.Note = resolveOptional(p.Note, "")
			}
			if err := store.ScopedByOrg(tx, orgID).Create(&row).Error; err != nil {
				return err
			}
		}
		for _, tg := range tags {
			row := model.AddressBookTag{
				OrganizationID: orgID,
				BookID:         book.ID,
				Name:           tg.Name,
				Color:          tg.Color,
			}
			if err := store.ScopedByOrg(tx, orgID).Create(&row).Error; err != nil {
				return err
			}
		}
		if err := bumpRevision(tx, orgID, book.ID); err != nil {
			return err
		}
		return store.ScopedByOrg(tx, orgID).First(&fresh, book.ID).Error
	})
	if err != nil {
		return nil, err
	}
	return &fresh, nil
}

// resolveOptional applies the legacy inheritance rule: a nil pointer means
// the field was omitted and the stored value carries over; an explicit
// value (including the empty string) replaces it.
func resolveOptional(incoming *string, stored string) string {
	if incoming == nil {
		return stored
	}
	return *incoming
}

// snapshotTx loads the book's peers and tags on the given transaction and
// maps them onto the compat wire shape.
func (s *Service) snapshotTx(tx *gorm.DB, orgID uint, book *model.AddressBook) (*BookSnapshot, error) {
	var peerRows []model.AddressBookPeer
	if err := store.ScopedByOrg(tx, orgID).
		Where("book_id = ?", book.ID).Order("id").Find(&peerRows).Error; err != nil {
		return nil, err
	}
	var tagRows []model.AddressBookTag
	if err := store.ScopedByOrg(tx, orgID).
		Where("book_id = ?", book.ID).Order("name").Find(&tagRows).Error; err != nil {
		return nil, err
	}
	peers := make([]PeerJSON, 0, len(peerRows))
	for _, p := range peerRows {
		peers = append(peers, peerToJSON(p))
	}
	return &BookSnapshot{Book: book, Peers: peers, Tags: tagRows}, nil
}

// mutateBook loads the book, checks ownership and runs fn inside a
// transaction holding the book row lock, bumping the revision on success.
func (s *Service) mutateBook(userID, orgID, bookID uint, fn func(tx *gorm.DB, book *model.AddressBook) error) error {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return err
	}
	if !canWrite(book, userID, "") {
		return ErrForbidden
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		current, err := lockBook(tx, orgID, book.ID)
		if err != nil {
			return err
		}
		if err := fn(tx, current); err != nil {
			return err
		}
		return bumpRevision(tx, orgID, current.ID)
	})
}

// rewritePeerTags decodes every peer's tag list in the book, applies fn and
// writes the result back (tag rename/delete cascades).
func rewritePeerTags(tx *gorm.DB, orgID, bookID uint, fn func([]string) []string) error {
	var rows []model.AddressBookPeer
	if err := store.ScopedByOrg(tx, orgID).
		Where("book_id = ?", bookID).Find(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		tags, err := DecodeTagsJSON(row.TagsJSON)
		if err != nil {
			return err
		}
		updated := fn(tags)
		if len(updated) == len(tags) && slicesEqual(updated, tags) {
			continue
		}
		if err := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookPeer{}).
			Where("id = ?", row.ID).
			Update("tags_json", TagsJSON(updated)).Error; err != nil {
			return err
		}
	}
	return nil
}

// slicesEqual reports whether two string slices hold the same elements in
// the same order (nil and empty are equal).
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
