package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type grantView struct {
	Id            int64  `json:"id"`
	SubjectKind   string `json:"subject_kind"`
	SubjectUserId *int64 `json:"subject_user_id"`
	Access        string `json:"access"`
	CreatedBy     int64  `json:"created_by"`
}

func TestAddressBookGrants_DelegationAndRevocation(t *testing.T) {
	h, orgID, _, _, member, ownerToken, adminToken, memberToken := m4Org(t)
	book := createBook(t, h, ownerToken, orgID, "team", "shared")
	bookID := book.Data.Id
	grantsPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(bookID) + "/grants"
	bookPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(bookID)
	peersPath := bookPath + "/peers"

	// Shared books stay readable by members, but grant management is full-only.
	w := h.do(t, http.MethodGet, bookPath, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, grantsPath, nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// The owner grants the member write access.
	w = h.do(t, http.MethodPost, grantsPath, map[string]any{
		"subject_kind": "user", "subject_user_id": member.ID, "access": "write",
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created grantView
	decodeData(t, w, &created)
	require.NotZero(t, created.Id)
	require.NotNil(t, created.SubjectUserId)
	require.EqualValues(t, member.ID, *created.SubjectUserId)

	// Write lets the member replace peers, but not rename the book.
	w = h.do(t, http.MethodPut, peersPath, map[string]any{
		"peers": []map[string]any{{"peer_id": "111111111"}},
	}, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPut, bookPath, map[string]string{"name": "renamed-by-member"}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Upgrading the same subject updates instead of duplicating.
	w = h.do(t, http.MethodPost, grantsPath, map[string]any{
		"subject_kind": "user", "subject_user_id": member.ID, "access": "full",
	}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var upgraded grantView
	decodeData(t, w, &upgraded)
	require.Equal(t, created.Id, upgraded.Id)
	require.Equal(t, "full", upgraded.Access)

	w = h.do(t, http.MethodGet, grantsPath, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var grants []grantView
	decodeData(t, w, &grants)
	require.Len(t, grants, 1)

	// Full access also allows the rename.
	w = h.do(t, http.MethodPut, bookPath, map[string]string{"name": "renamed-by-member"}, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Revoking the grant returns the member to read-only.
	w = h.do(t, http.MethodDelete, grantsPath+"/"+itoa(created.Id), nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPut, peersPath, map[string]any{
		"peers": []map[string]any{{"peer_id": "222222222"}},
	}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, grantsPath+"/"+itoa(created.Id), nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// An admin may manage grants through the builtin addressbook permission.
	w = h.do(t, http.MethodPost, grantsPath, map[string]any{
		"subject_kind": "everyone", "access": "write",
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var everyone grantView
	decodeData(t, w, &everyone)
	require.Nil(t, everyone.SubjectUserId, "the everyone grant has no subject id")

	// The everyone write grant reaches the member.
	w = h.do(t, http.MethodPut, peersPath, map[string]any{
		"peers": []map[string]any{{"peer_id": "333333333"}},
	}, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestAddressBookGrants_ValidationAndIsolation(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, memberToken := m4Org(t)
	shared := createBook(t, h, ownerToken, orgID, "team", "shared")
	personal := createBook(t, h, ownerToken, orgID, "mine", "personal")
	sharedPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(shared.Data.Id) + "/grants"
	personalPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(personal.Data.Id) + "/grants"

	w := h.do(t, http.MethodPost, sharedPath, map[string]any{
		"subject_kind": "user", "subject_user_id": 424242, "access": "read",
	}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, sharedPath, map[string]any{
		"subject_kind": "user", "access": "read",
	}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, sharedPath, map[string]any{
		"subject_kind": "everyone", "access": "owner",
	}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, sharedPath, map[string]any{
		"subject_kind": "team", "access": "read",
	}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Personal books have no grants.
	w = h.do(t, http.MethodPost, personalPath, map[string]any{
		"subject_kind": "everyone", "access": "read",
	}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Another tenant cannot read this book's grants.
	h.seedUser(t, "grant-other@example.com", "password123")
	otherToken := h.login(t, "grant-other@example.com", "password123")
	createOrg(t, h, otherToken, "grant-other-org")
	w = h.do(t, http.MethodGet, sharedPath, nil, otherToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// The member cannot self-elevate.
	w = h.do(t, http.MethodPost, sharedPath, map[string]any{
		"subject_kind": "everyone", "access": "full",
	}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
