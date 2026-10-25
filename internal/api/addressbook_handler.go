package api

import (
	"errors"
	"math"
	"net/http"

	"unicode/utf8"

	"go.uber.org/zap"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/addressbook"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// respondBook renders the common address book envelope.
func respondBook(c *gin.Context, status int, book *model.AddressBook) {
	var owner *int64
	if book.OwnerID != nil {
		v := int64(*book.OwnerID)
		owner = &v
	}
	c.JSON(status, gen.AddressBookResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.AddressBook{
			Id:        int64(book.ID),
			Name:      book.Name,
			Scope:     gen.AddressBookScope(book.Scope),
			OwnerId:   owner,
			Revision:  int64(book.Revision),
			CreatedAt: book.CreatedAt,
			UpdatedAt: book.UpdatedAt,
		},
	})
}

// mapBookError translates service errors into the standard envelope.
func mapBookError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, addressbook.ErrBookNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "address book not found")
	case errors.Is(err, addressbook.ErrForbidden):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "not allowed to modify this address book")
	case errors.Is(err, addressbook.ErrDuplicateName):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "address book name already exists")
	case errors.Is(err, model.ErrAddressBookScopeInvalid):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "scope must be personal or shared")
	default:
		return false
	}
	return true
}

// ListAddressBooks returns shared books of the org plus the caller's own
// personal books.
func (a *AdminAPI) ListAddressBooks(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if _, member := a.membershipFor(c, uid, uint(orgId)); !member {
		return
	}

	books, err := a.books.List(uid, uint(orgId))
	if err != nil && !mapBookError(c, err) {
		a.deps.Logger.Error("list address books failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list address books")
		return
	}

	out := make([]gen.AddressBook, 0, len(books))
	for i := range books {
		b := &books[i]
		item := bookToGen(b)
		out = append(out, item)
	}
	c.JSON(http.StatusOK, gen.AddressBookListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateAddressBook adds a personal or shared book. Shared creation requires
// the addressbook write permission.
func (a *AdminAPI) CreateAddressBook(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	var req gen.CreateAddressBookJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil || !validBookName(req.Name) {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "name must be non-empty and at most 128 characters")
		return
	}

	if req.Scope == gen.AddressBookCreateRequestScopeShared {
		if _, member := a.membershipFor(c, uid, uint(orgId)); !member {
			return
		}
		perms, _ := authz.OrgPermissions(c)
		if !a.requireBookWriteScope(c, perms) {
			return
		}
		if !canWriteShared(perms) {
			abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
			return
		}
	} else {
		if _, member := a.membershipFor(c, uid, uint(orgId)); !member {
			return
		}
		if perms, _ := authz.OrgPermissions(c); !a.requireBookWriteScope(c, perms) {
			return
		}
	}

	book, err := a.books.Create(uid, uint(orgId), string(req.Scope), req.Name)
	if err != nil && mapBookError(c, err) {
		return
	}
	if err != nil {
		a.deps.Logger.Error("create address book failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create address book")
		return
	}
	respondBook(c, http.StatusCreated, book)
}

// GetAddressBook returns the book with its peers and tags.
func (a *AdminAPI) GetAddressBook(c *gin.Context, orgId int64, bookId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	book, peers, tags, err := a.loadBook(c, uid, orgId, bookId)
	if err != nil {
		return
	}

	item := bookToGen(book)
	peerList := make([]gen.AddressBookPeer, 0, len(peers))
	for _, p := range peers {
		tags, derr := addressbook.DecodeTagsJSON(p.TagsJSON)
		if derr != nil {
			a.deps.Logger.Error("decode peer tags failed")
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load address book")
			return
		}
		peerList = append(peerList, peerToGen(p, tags))
	}
	item.Peers = &peerList

	tagList := make([]gen.AddressBookTag, 0, len(tags))
	for _, tg := range tags {
		color := int(tg.Color)
		tagList = append(tagList, gen.AddressBookTag{Name: tg.Name, Color: &color})
	}
	item.Tags = &tagList

	c.JSON(http.StatusOK, gen.AddressBookResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: item})
}

// UpdateAddressBook renames the book (scope is immutable).
func (a *AdminAPI) UpdateAddressBook(c *gin.Context, orgId int64, bookId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.UpdateAddressBookJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil || !validBookName(req.Name) {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "name must be non-empty and at most 128 characters")
		return
	}

	role, ok := a.roleForBook(c, uid, orgId, bookId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, role) {
		return
	}
	book, err := a.books.Update(uid, role, uint(orgId), uint(bookId), req.Name)
	if err != nil && mapBookError(c, err) {
		return
	}
	if err != nil {
		a.deps.Logger.Error("update address book failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update address book")
		return
	}
	respondBook(c, http.StatusOK, book)
}

// DeleteAddressBook removes the book and cascades peers and tags.
func (a *AdminAPI) DeleteAddressBook(c *gin.Context, orgId int64, bookId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	role, ok := a.roleForBook(c, uid, orgId, bookId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, role) {
		return
	}
	book, err := a.books.Delete(uid, role, uint(orgId), uint(bookId))
	if err != nil && mapBookError(c, err) {
		return
	}
	if err != nil {
		a.deps.Logger.Error("delete address book failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not delete address book")
		return
	}
	respondBook(c, http.StatusOK, book)
}

// tooManyRunes reports whether s exceeds max Unicode characters. Column
// widths are varchar(n) in character semantics, so byte counting would
// wrongly reject legitimate multi-byte (e.g. Chinese) values.
func tooManyRunes(s string, max int) bool {
	return utf8.RuneCountInString(s) > max
}

// validatePeers enforces the column widths (in characters) and per-request
// uniqueness so a bad payload comes back as 400 instead of surfacing as a
// 500 from a varchar or unique-index failure mid-transaction.
// Contract bounds enforced here because no request validator is mounted: the
// generated binder accepts any array length and any integer. The limits live in
// the addressbook package so the compat write path enforces the same numbers.

func validatePeers(peers []gen.AddressBookPeer) bool {
	if len(peers) > addressbook.MaxPeersPerBook {
		return false
	}
	seen := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		if p.PeerId == "" || tooManyRunes(p.PeerId, 64) {
			return false
		}
		if p.Tags != nil && len(*p.Tags) > addressbook.MaxTagsPerPeer {
			return false
		}
		if tooManyRunes(deref(p.Alias), 128) ||
			tooManyRunes(deref(p.Username), 128) ||
			tooManyRunes(deref(p.Hostname), 128) ||
			tooManyRunes(deref(p.Platform), 64) {
			return false
		}
		// The encoded TagsJSON must fit its column; encode with the same
		// function the service persists with, so escaping is accounted for.
		if encoded := addressbook.TagsJSON(derefStrings(p.Tags)); tooManyRunes(encoded, 2048) {
			return false
		}
		if _, dup := seen[p.PeerId]; dup {
			return false
		}
		seen[p.PeerId] = struct{}{}
	}
	return true
}

// validateTags is the tag-name counterpart of validatePeers.
func validateTags(tags []gen.AddressBookTag) bool {
	if len(tags) > addressbook.MaxTagsPerBook {
		return false
	}
	seen := make(map[string]struct{}, len(tags))
	for _, tg := range tags {
		if tg.Name == "" || tooManyRunes(tg.Name, 64) {
			return false
		}
		// The colour is stored as uint32; an out-of-range value would be
		// silently truncated instead of rejected.
		if tg.Color != nil && (*tg.Color < 0 || int64(*tg.Color) > math.MaxUint32) {
			return false
		}
		if _, dup := seen[tg.Name]; dup {
			return false
		}
		seen[tg.Name] = struct{}{}
	}
	return true
}

// validBookName checks the varchar(128) bound for book names.
func validBookName(name string) bool {
	return name != "" && !tooManyRunes(name, 128)
}

// ReplaceAddressBookPeers swaps the full peer list.
func (a *AdminAPI) ReplaceAddressBookPeers(c *gin.Context, orgId int64, bookId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.ReplaceAddressBookPeersJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid peers payload")
		return
	}

	role, ok := a.roleForBook(c, uid, orgId, bookId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, role) {
		return
	}
	if !validatePeers(req.Peers) {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
			"peer_id must be non-empty, at most 64 characters and unique within the request")
		return
	}

	inputs := make([]addressbook.PeerInput, 0, len(req.Peers))
	for _, p := range req.Peers {
		inputs = append(inputs, addressbook.PeerInput{
			PeerID:   p.PeerId,
			Alias:    deref(p.Alias),
			Username: deref(p.Username),
			Hostname: deref(p.Hostname),
			Platform: deref(p.Platform),
			Tags:     derefStrings(p.Tags),
		})
	}

	book, err := a.books.ReplacePeers(uid, role, uint(orgId), uint(bookId), inputs)
	if err != nil && mapBookError(c, err) {
		return
	}
	if err != nil {
		a.deps.Logger.Error("replace address book peers failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not replace peers")
		return
	}
	respondBook(c, http.StatusOK, book)
}

// ReplaceAddressBookTags swaps the full tag list.
func (a *AdminAPI) ReplaceAddressBookTags(c *gin.Context, orgId int64, bookId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.ReplaceAddressBookTagsJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid tags payload")
		return
	}

	role, ok := a.roleForBook(c, uid, orgId, bookId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, role) {
		return
	}
	if !validateTags(req.Tags) {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
			"tag name must be non-empty, at most 64 characters and unique within the request")
		return
	}

	inputs := make([]addressbook.TagInput, 0, len(req.Tags))
	for _, tg := range req.Tags {
		color := uint32(0)
		if tg.Color != nil {
			color = uint32(*tg.Color)
		}
		inputs = append(inputs, addressbook.TagInput{Name: tg.Name, Color: color})
	}

	book, err := a.books.ReplaceTags(uid, role, uint(orgId), uint(bookId), inputs)
	if err != nil && mapBookError(c, err) {
		return
	}
	if err != nil {
		a.deps.Logger.Error("replace address book tags failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not replace tags")
		return
	}
	respondBook(c, http.StatusOK, book)
}

// ListAddressBookGrants lists the grants of a shared book. Grant management
// requires full access.
func (a *AdminAPI) ListAddressBookGrants(c *gin.Context, orgId int64, bookId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	perms, ok := a.roleForBook(c, uid, orgId, bookId)
	if !ok {
		return
	}
	grants, err := a.books.ListGrants(uid, uint(orgId), uint(bookId), perms)
	if err != nil && mapGrantError(c, err) {
		return
	}
	if err != nil {
		a.deps.Logger.Error("list address book grants failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list grants")
		return
	}
	out := make([]gen.AddressBookGrant, 0, len(grants))
	for i := range grants {
		out = append(out, grantToGen(&grants[i]))
	}
	c.JSON(http.StatusOK, gen.AddressBookGrantListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateAddressBookGrant creates or updates one subject's grant.
func (a *AdminAPI) CreateAddressBookGrant(c *gin.Context, orgId int64, bookId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.AddressBookGrantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid grant payload")
		return
	}
	var subjectUserID uint
	if req.SubjectUserId != nil {
		if *req.SubjectUserId <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "subject_user_id must be positive")
			return
		}
		subjectUserID = uint(*req.SubjectUserId)
	}
	perms, ok := a.roleForBook(c, uid, orgId, bookId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, perms) {
		return
	}

	grant, created, err := a.books.UpsertGrant(uid, uint(orgId), uint(bookId), subjectUserID,
		string(req.SubjectKind), string(req.Access), perms)
	if err != nil && mapGrantError(c, err) {
		return
	}
	if err != nil {
		a.deps.Logger.Error("create address book grant failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update grant")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, gen.AddressBookGrantResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: grantToGen(grant)})
}

// DeleteAddressBookGrant revokes one grant of a shared book.
func (a *AdminAPI) DeleteAddressBookGrant(c *gin.Context, orgId int64, bookId int64, grantId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if grantId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid grant id")
		return
	}
	perms, ok := a.roleForBook(c, uid, orgId, bookId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, perms) {
		return
	}
	if err := a.books.DeleteGrant(uid, uint(orgId), uint(bookId), uint(grantId), perms); err != nil {
		if mapGrantError(c, err) {
			return
		}
		a.deps.Logger.Error("delete address book grant failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not delete grant")
		return
	}
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// mapGrantError translates grant-specific service errors; shared cases defer to
// mapBookError.
func mapGrantError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, addressbook.ErrInvalidGrant):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, addressbook.ErrGrantNotShared):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, addressbook.ErrSubjectNotMember):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, addressbook.ErrGrantNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "grant not found")
	default:
		return mapBookError(c, err)
	}
	return true
}

// grantToGen maps a grant row onto the contract shape. subject_user_id is
// omitted for the everyone grant.
func grantToGen(g *model.AddressBookGrant) gen.AddressBookGrant {
	out := gen.AddressBookGrant{
		Id:          int64(g.ID),
		SubjectKind: gen.AddressBookGrantKind(g.SubjectKind),
		Access:      gen.AddressBookGrantAccess(g.Access),
		CreatedBy:   int64(g.CreatedBy),
		CreatedAt:   g.CreatedAt,
	}
	if g.SubjectKind == model.GrantSubjectUser {
		id := int64(g.SubjectUserID)
		out.SubjectUserId = &id
	}
	return out
}

// DeleteAddressBookPeer moves one peer to the recycle bin.
func (a *AdminAPI) DeleteAddressBookPeer(c *gin.Context, orgId int64, bookId int64, peerId string) {
	uid, perms, ok := a.peerBookContext(c, orgId, bookId, peerId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, perms) {
		return
	}
	if err := a.books.DeletePeer(uid, perms, uint(orgId), uint(bookId), peerId); err != nil {
		a.writePeerError(c, err, "delete address book peer failed")
		return
	}
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// ListAddressBookRecycleBin lists the soft-deleted peers of a book.
func (a *AdminAPI) ListAddressBookRecycleBin(c *gin.Context, orgId int64, bookId int64) {
	uid, perms, ok := a.peerBookContext(c, orgId, bookId, "")
	if !ok {
		return
	}
	rows, err := a.books.ListRecycleBin(uid, perms, uint(orgId), uint(bookId))
	if err != nil {
		a.writePeerError(c, err, "list recycle bin failed")
		return
	}
	out := make([]gen.AddressBookRecycleBinItem, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		item := gen.AddressBookRecycleBinItem{
			PeerId:    row.PeerID,
			DeletedAt: *row.DeletedAt,
			DeletedBy: int64(row.DeletedBy),
		}
		if row.Alias != "" {
			v := row.Alias
			item.Alias = &v
		}
		if row.Username != "" {
			v := row.Username
			item.Username = &v
		}
		if row.Hostname != "" {
			v := row.Hostname
			item.Hostname = &v
		}
		if row.Platform != "" {
			v := row.Platform
			item.Platform = &v
		}
		if tags, derr := addressbook.DecodeTagsJSON(row.TagsJSON); derr == nil && len(tags) > 0 {
			item.Tags = &tags
		}
		out = append(out, item)
	}
	c.JSON(http.StatusOK, gen.AddressBookRecycleBinResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// RestoreAddressBookPeer returns one recycled peer to the live list.
func (a *AdminAPI) RestoreAddressBookPeer(c *gin.Context, orgId int64, bookId int64, peerId string) {
	uid, perms, ok := a.peerBookContext(c, orgId, bookId, peerId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, perms) {
		return
	}
	if err := a.books.RestorePeer(uid, perms, uint(orgId), uint(bookId), peerId); err != nil {
		a.writePeerError(c, err, "restore address book peer failed")
		return
	}
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// PurgeAddressBookPeer permanently deletes one recycled peer.
func (a *AdminAPI) PurgeAddressBookPeer(c *gin.Context, orgId int64, bookId int64, peerId string) {
	uid, perms, ok := a.peerBookContext(c, orgId, bookId, peerId)
	if !ok {
		return
	}
	if !a.requireBookWriteScope(c, perms) {
		return
	}
	if err := a.books.PurgePeer(uid, perms, uint(orgId), uint(bookId), peerId); err != nil {
		a.writePeerError(c, err, "purge address book peer failed")
		return
	}
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// peerBookContext validates ids, checks membership and returns the caller's
// permission set. A non-empty peerId is validated against the contract bound.
func (a *AdminAPI) peerBookContext(c *gin.Context, orgId, bookId int64, peerId string) (uint, []string, bool) {
	uid, ok := requireUserID(c)
	if !ok {
		return 0, nil, false
	}
	if orgId <= 0 || bookId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return 0, nil, false
	}
	if peerId != "" && tooManyRunes(peerId, 64) {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "peer id is too long")
		return 0, nil, false
	}
	perms, ok := a.roleForBook(c, uid, orgId, bookId)
	if !ok {
		return 0, nil, false
	}
	return uid, perms, true
}

// writePeerError maps recycle-bin errors onto the standard envelope.
func (a *AdminAPI) writePeerError(c *gin.Context, err error, logMsg string) {
	if errors.Is(err, addressbook.ErrPeerNotFound) {
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "address book peer not found")
		return
	}
	if errors.Is(err, addressbook.ErrInvalidContent) {
		// Restoring a peer can exceed the per-book limit; that is a client
		// conflict with the book state, not a server failure.
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}
	if mapBookError(c, err) {
		return
	}
	a.deps.Logger.Error(logMsg)
	abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update address book")
}

// loadBook resolves the caller's role and fetches the book with peers/tags,
// mapping service errors onto the standard envelope.
func (a *AdminAPI) loadBook(c *gin.Context, uid uint, orgId, bookId int64) (*model.AddressBook, []model.AddressBookPeer, []model.AddressBookTag, error) {
	if orgId <= 0 || bookId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return nil, nil, nil, errStop
	}
	if _, member := a.membershipFor(c, uid, uint(orgId)); !member {
		return nil, nil, nil, errStop
	}
	book, peers, tags, err := a.books.Get(uid, uint(orgId), uint(bookId))
	if err != nil && mapBookError(c, err) {
		return nil, nil, nil, errStop
	}
	if err != nil {
		a.deps.Logger.Error("get address book failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load address book")
		return nil, nil, nil, errStop
	}
	return book, peers, tags, nil
}

// roleForBook resolves the caller's permission set after checking membership;
// it does not load the book (the service enforces personal-book rules).
func (a *AdminAPI) roleForBook(c *gin.Context, uid uint, orgId, bookId int64) ([]string, bool) {
	if orgId <= 0 || bookId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return nil, false
	}
	if _, member := a.membershipFor(c, uid, uint(orgId)); !member {
		return nil, false
	}
	perms, _ := authz.OrgPermissions(c)
	return perms, true
}

func canWriteShared(perms []string) bool {
	return authz.Has(perms, authz.PermAddressBook)
}

// requireBookWriteScope applies the personal-token ceiling to address-book
// mutations. Ownership and grants can authorize write/full access independently
// of the role permission, so without this check a token minted with unrelated
// permissions (for example device.read only) could still delete its user's
// personal book or a book the user holds a full grant on. The token's effective
// set is the upper bound; JWT callers are unaffected.
func (a *AdminAPI) requireBookWriteScope(c *gin.Context, perms []string) bool {
	if _, tokenAuth := auth.TokenPermissions(c); tokenAuth && !authz.Has(perms, authz.PermAddressBook) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "personal token lacks addressbook.write")
		return false
	}
	return true
}

// errStop marks "response already written" inside the load helpers.
var errStop = errors.New("stop")

// bookToGen converts the model row into the contract shape (peers and tags
// omitted; Get fills them separately).
func bookToGen(b *model.AddressBook) gen.AddressBook {
	var owner *int64
	if b.OwnerID != nil {
		v := int64(*b.OwnerID)
		owner = &v
	}
	return gen.AddressBook{
		Id:        int64(b.ID),
		Name:      b.Name,
		Scope:     gen.AddressBookScope(b.Scope),
		OwnerId:   owner,
		Revision:  int64(b.Revision),
		CreatedAt: b.CreatedAt,
		UpdatedAt: b.UpdatedAt,
	}
}

// peerToGen converts a stored peer; empty optional fields stay unset.
func peerToGen(p model.AddressBookPeer, tags []string) gen.AddressBookPeer {
	out := gen.AddressBookPeer{PeerId: p.PeerID}
	if p.Alias != "" {
		v := p.Alias
		out.Alias = &v
	}
	if p.Username != "" {
		v := p.Username
		out.Username = &v
	}
	if p.Hostname != "" {
		v := p.Hostname
		out.Hostname = &v
	}
	if p.Platform != "" {
		v := p.Platform
		out.Platform = &v
	}
	if len(tags) > 0 {
		out.Tags = &tags
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefStrings(s *[]string) []string {
	if s == nil {
		return nil
	}
	return *s
}
