package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type recycleBinItem struct {
	PeerId    string     `json:"peer_id"`
	Alias     *string    `json:"alias"`
	DeletedAt *time.Time `json:"deleted_at"`
	DeletedBy int64      `json:"deleted_by"`
}

func TestAddressBookRecycleBin_DeleteRestoreAndPurge(t *testing.T) {
	h, orgID, owner, _, _, ownerToken, adminToken, memberToken := m4Org(t)
	book := createBook(t, h, ownerToken, orgID, "team", "shared")
	bookID := book.Data.Id
	bookPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(bookID)
	peersPath := bookPath + "/peers"
	binPath := bookPath + "/recycle-bin"

	w := h.do(t, http.MethodPut, peersPath, map[string]any{
		"peers": []map[string]any{{"peer_id": "111111111", "alias": "one"}, {"peer_id": "222222222"}},
	}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// A member without a write grant cannot delete.
	w = h.do(t, http.MethodDelete, peersPath+"/222222222", nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Deleting moves the entry to the recycle bin instead of destroying it.
	w = h.do(t, http.MethodDelete, peersPath+"/222222222", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, bookPath, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var bookView struct {
		Data struct {
			Peers []struct {
				PeerId string `json:"peer_id"`
			} `json:"peers"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &bookView))
	require.Len(t, bookView.Data.Peers, 1)
	require.Equal(t, "111111111", bookView.Data.Peers[0].PeerId)

	w = h.do(t, http.MethodGet, binPath, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var bin []recycleBinItem
	decodeData(t, w, &bin)
	require.Len(t, bin, 1)
	require.Equal(t, "222222222", bin[0].PeerId)
	require.NotNil(t, bin[0].DeletedAt)
	require.EqualValues(t, owner.ID, bin[0].DeletedBy)

	// A deleted peer cannot be deleted twice; restoring brings it back.
	w = h.do(t, http.MethodDelete, peersPath+"/222222222", nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, binPath+"/222222222/restore", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, binPath, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &bin)
	require.Empty(t, bin)

	// Purging is permanent.
	w = h.do(t, http.MethodDelete, peersPath+"/222222222", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, binPath+"/222222222", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, binPath+"/222222222", nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, binPath+"/222222222/restore", nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// The admin (addressbook.write) sees the same surfaces.
	w = h.do(t, http.MethodDelete, peersPath+"/111111111", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, binPath, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &bin)
	require.Len(t, bin, 1)
}

func TestAddressBookRecycleBin_DelegatedWriteButNotPurge(t *testing.T) {
	h, orgID, _, _, member, ownerToken, _, memberToken := m4Org(t)
	book := createBook(t, h, ownerToken, orgID, "team", "shared")
	bookID := book.Data.Id
	bookPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(bookID)
	peersPath := bookPath + "/peers"
	binPath := bookPath + "/recycle-bin"

	grantsPath := bookPath + "/grants"
	w := h.do(t, http.MethodPost, grantsPath, map[string]any{
		"subject_kind": "user", "subject_user_id": member.ID, "access": "write",
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = h.do(t, http.MethodPut, peersPath, map[string]any{
		"peers": []map[string]any{{"peer_id": "333333333"}},
	}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Delegated write can delete/list/restore, but permanent deletion is full-only.
	w = h.do(t, http.MethodDelete, peersPath+"/333333333", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, binPath, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, binPath+"/333333333", nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, binPath+"/333333333/restore", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Cross-tenant access is a 403.
	h.seedUser(t, "bin-other@example.com", "password123")
	otherToken := h.login(t, "bin-other@example.com", "password123")
	createOrg(t, h, otherToken, "bin-other-org")
	w = h.do(t, http.MethodGet, binPath, nil, otherToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// A personal book also has a recycle bin (its owner may use it).
	personal := createBook(t, h, ownerToken, orgID, "mine", "personal")
	personalPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(personal.Data.Id)
	w = h.do(t, http.MethodGet, personalPath+"/recycle-bin", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, personalPath+"/recycle-bin", nil, memberToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}
