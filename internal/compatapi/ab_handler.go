// Address book client sync (task 9). The RustDesk client talks two dialects:
//
//   - legacy whole-book mode (Sciter era): GET returns {"data": "<json
//     string>"} and POST replaces the book with {"data": "<json string>"};
//   - 1.4+ granular mode: POST /api/ab/personal returns the book guid, then
//     the client drives paged peer fetches and one-peer/one-tag mutations.
//
// M2 maps both dialects onto the logged-in user's personal book inside the
// session-bound organization. Payload shapes follow the official client
// source (flutter/lib/models/ab_model.dart, hbbs.dart, peer_model.dart);
// frozen fixtures live in testdata/.
package compatapi

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/addressbook"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// abPeer is the client's wire shape of one address book peer entry
// (Peer.toCustomJson plus the note field the update endpoint accepts).
type abPeer = addressbook.PeerJSON

// resolvePersonalBook parses the guid path parameter and loads the book,
// enforcing that it belongs to the session user (personal scope) inside the
// session-bound organization.
func (s *Server) resolvePersonalBook(c *gin.Context) (*model.AddressBook, bool) {
	uid, orgID, _ := sessionFrom(c)
	id, err := strconv.ParseUint(c.Param("guid"), 10, 64)
	if err != nil {
		compatError(c, http.StatusNotFound, "address book not found")
		return nil, false
	}
	book, _, _, err := s.deps.Books.Get(uid, orgID, uint(id))
	if err != nil {
		compatError(c, http.StatusNotFound, "address book not found")
		return nil, false
	}
	return book, true
}

// abPersonal answers the mode probe: the client treats a 200 guid as "new
// mode" and a 404 as "legacy mode" (rustdesk ab_model.dart: _getPersonalAbGuid).
func (s *Server) abPersonal(c *gin.Context) {
	uid, orgID, _ := sessionFrom(c)
	book, err := s.deps.Books.EnsurePersonalBook(uid, orgID)
	if err != nil {
		compatError(c, http.StatusInternalServerError, "could not open address book")
		return
	}
	c.JSON(http.StatusOK, gin.H{"guid": strconv.FormatUint(uint64(book.ID), 10)})
}

// abPeersPage serves the paged peer list (POST /api/ab/peers?current&pageSize&ab).
// The book guid arrives as the `ab` query parameter, not a path segment.
func (s *Server) abPeersPage(c *gin.Context) {
	uid, orgID, _ := sessionFrom(c)
	id, err := strconv.ParseUint(c.Query("ab"), 10, 64)
	if err != nil {
		compatError(c, http.StatusNotFound, "address book not found")
		return
	}
	current, err := strconv.Atoi(c.DefaultQuery("current", "1"))
	if err != nil || current < 1 {
		current = 1
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("pageSize", "100"))
	if err != nil || pageSize < 1 {
		pageSize = 100
	}
	if pageSize > 500 {
		pageSize = 500
	}

	snap, err := s.deps.Books.SnapshotForCompat(uid, orgID, uint(id))
	if err != nil {
		compatError(c, http.StatusNotFound, "address book not found")
		return
	}
	total := len(snap.Peers)
	offset := (current - 1) * pageSize
	if offset > total {
		offset = total
	}
	end := offset + pageSize
	if end > total {
		end = total
	}
	c.JSON(http.StatusOK, gin.H{
		"total": total,
		"data":  snap.Peers[offset:end],
	})
}

// abTagsList serves the tag list as a bare JSON array
// (POST /api/ab/tags/{guid} → [{name, color}]).
func (s *Server) abTagsList(c *gin.Context) {
	book, found := s.resolvePersonalBook(c)
	if !found {
		return
	}
	uid, orgID, _ := sessionFrom(c)
	_, _, tags, err := s.deps.Books.Get(uid, orgID, book.ID)
	if err != nil {
		compatError(c, http.StatusNotFound, "address book not found")
		return
	}
	out := make([]gin.H, 0, len(tags))
	for _, t := range tags {
		out = append(out, gin.H{"name": t.Name, "color": t.Color})
	}
	c.JSON(http.StatusOK, out)
}

// abPeerAdd upserts one peer (POST /api/ab/peer/add/{guid}).
func (s *Server) abPeerAdd(c *gin.Context) {
	book, found := s.resolvePersonalBook(c)
	if !found {
		return
	}
	uid, orgID, _ := sessionFrom(c)
	var p abPeer
	if err := c.ShouldBindJSON(&p); err != nil || p.ID == "" {
		compatError(c, http.StatusBadRequest, "invalid peer payload")
		return
	}
	if err := s.deps.Books.AddPeer(uid, orgID, book.ID, p); err != nil {
		s.abActionError(c, err)
		return
	}
	ok(c)
}

// abPeerUpdate applies a partial field update (PUT /api/ab/peer/update/{guid}).
func (s *Server) abPeerUpdate(c *gin.Context) {
	book, found := s.resolvePersonalBook(c)
	if !found {
		return
	}
	uid, orgID, _ := sessionFrom(c)
	var fields map[string]any
	if err := c.ShouldBindJSON(&fields); err != nil {
		compatError(c, http.StatusBadRequest, "invalid peer payload")
		return
	}
	peerID, _ := fields["id"].(string)
	if peerID == "" {
		compatError(c, http.StatusBadRequest, "invalid peer payload")
		return
	}
	if err := s.deps.Books.UpdatePeer(uid, orgID, book.ID, peerID, fields); err != nil {
		s.abActionError(c, err)
		return
	}
	ok(c)
}

// abPeerDelete removes the listed peer ids (DELETE /api/ab/peer/{guid},
// body is a bare JSON array of ids).
func (s *Server) abPeerDelete(c *gin.Context) {
	book, found := s.resolvePersonalBook(c)
	if !found {
		return
	}
	uid, orgID, _ := sessionFrom(c)
	var ids []string
	if err := c.ShouldBindJSON(&ids); err != nil || len(ids) == 0 {
		compatError(c, http.StatusBadRequest, "invalid peer payload")
		return
	}
	if err := s.deps.Books.DeletePeers(uid, orgID, book.ID, ids); err != nil {
		s.abActionError(c, err)
		return
	}
	ok(c)
}

// abTagAdd creates a tag (POST /api/ab/tag/add/{guid}, {"name", "color"}).
func (s *Server) abTagAdd(c *gin.Context) {
	book, found := s.resolvePersonalBook(c)
	if !found {
		return
	}
	uid, orgID, _ := sessionFrom(c)
	var req struct {
		Name  string `json:"name"`
		Color int64  `json:"color"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		compatError(c, http.StatusBadRequest, "invalid tag payload")
		return
	}
	if err := s.deps.Books.AddTag(uid, orgID, book.ID, req.Name, uint32(req.Color)); err != nil {
		s.abActionError(c, err)
		return
	}
	ok(c)
}

// abTagRename renames a tag (PUT /api/ab/tag/rename/{guid}, {"old", "new"}).
func (s *Server) abTagRename(c *gin.Context) {
	book, found := s.resolvePersonalBook(c)
	if !found {
		return
	}
	uid, orgID, _ := sessionFrom(c)
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Old == "" || req.New == "" {
		compatError(c, http.StatusBadRequest, "invalid tag payload")
		return
	}
	if err := s.deps.Books.RenameTag(uid, orgID, book.ID, req.Old, req.New); err != nil {
		s.abActionError(c, err)
		return
	}
	ok(c)
}

// abTagUpdate changes a tag's color (PUT /api/ab/tag/update/{guid}).
func (s *Server) abTagUpdate(c *gin.Context) {
	book, found := s.resolvePersonalBook(c)
	if !found {
		return
	}
	uid, orgID, _ := sessionFrom(c)
	var req struct {
		Name  string `json:"name"`
		Color int64  `json:"color"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		compatError(c, http.StatusBadRequest, "invalid tag payload")
		return
	}
	if err := s.deps.Books.UpdateTagColor(uid, orgID, book.ID, req.Name, uint32(req.Color)); err != nil {
		s.abActionError(c, err)
		return
	}
	ok(c)
}

// abTagDelete removes a tag (DELETE /api/ab/tag/{guid}, body ["tag"]).
func (s *Server) abTagDelete(c *gin.Context) {
	book, found := s.resolvePersonalBook(c)
	if !found {
		return
	}
	uid, orgID, _ := sessionFrom(c)
	var names []string
	if err := c.ShouldBindJSON(&names); err != nil || len(names) == 0 {
		compatError(c, http.StatusBadRequest, "invalid tag payload")
		return
	}
	for _, name := range names {
		if err := s.deps.Books.DeleteTag(uid, orgID, book.ID, name); err != nil {
			s.abActionError(c, err)
			return
		}
	}
	ok(c)
}

// abActionError maps service errors onto the client's {"error": msg} shape.
func (s *Server) abActionError(c *gin.Context, err error) {
	switch err {
	case addressbook.ErrBookNotFound:
		compatError(c, http.StatusNotFound, "address book entry not found")
	case addressbook.ErrForbidden:
		compatError(c, http.StatusForbidden, "not allowed")
	default:
		compatError(c, http.StatusInternalServerError, "address book update failed")
	}
}

// legacyEnvelope is the legacy /api/ab POST body.
type legacyEnvelope struct {
	Data string `json:"data"`
	Hash string `json:"hash"`
}

// abLegacyGet answers GET /api/ab (and the /api/ab/get Sciter alias) with
// the whole book as a JSON-encoded string; an empty body of `null` means an
// empty book. The envelope carries the content hash for optimistic
// concurrency on push.
func (s *Server) abLegacyGet(c *gin.Context) {
	uid, orgID, _ := sessionFrom(c)
	snap, err := s.deps.Books.SnapshotForCompatPersonal(uid, orgID)
	if err != nil {
		compatError(c, http.StatusInternalServerError, "could not open address book")
		return
	}
	if snap == nil {
		// No personal book yet: the client clears its local copy.
		c.JSON(http.StatusOK, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": addressbook.EncodeLegacyContent(snap),
		"hash": legacyHash(snap),
	})
}

// abLegacyPost replaces the whole book (legacy push). A stale content hash
// in the request aborts with 409 ab_conflict (Review Focus #5).
func (s *Server) abLegacyPost(c *gin.Context) {
	uid, orgID, _ := sessionFrom(c)
	var env legacyEnvelope
	if err := c.ShouldBindJSON(&env); err != nil || env.Data == "" {
		compatError(c, http.StatusBadRequest, "invalid address book payload")
		return
	}

	snap, err := s.deps.Books.SnapshotForCompatPersonal(uid, orgID)
	if err != nil {
		compatError(c, http.StatusInternalServerError, "could not open address book")
		return
	}
	if snap != nil && env.Hash != "" && env.Hash != legacyHash(snap) {
		// The client's copy is based on another revision; replacing would
		// silently drop whichever side pushed last.
		compatError(c, http.StatusConflict, "ab_conflict")
		return
	}

	content, err := addressbook.DecodeLegacyContent(env.Data)
	if err != nil {
		compatError(c, http.StatusBadRequest, "invalid address book payload")
		return
	}
	tags := make([]addressbook.TagInput, 0, len(content.Tags))
	for _, name := range content.Tags {
		tags = append(tags, addressbook.TagInput{Name: name, Color: content.Colors[name]})
	}

	book, err := s.deps.Books.EnsurePersonalBook(uid, orgID)
	if err != nil {
		compatError(c, http.StatusInternalServerError, "could not open address book")
		return
	}
	if _, err := s.deps.Books.ReplaceBookContent(uid, orgID, book.ID, content.Peers, tags); err != nil {
		s.abActionError(c, err)
		return
	}
	ok(c)
}

// legacyHash derives the deterministic content hash used for conflict
// detection on the legacy push path.
func legacyHash(snap *addressbook.BookSnapshot) string {
	return addressbook.ContentHash(snap)
}
