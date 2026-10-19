package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
)

// inviteAndJoin creates an invitation directly and joins the user, returning
// their bearer token.
func inviteAndJoin(t *testing.T, h *harness, orgID int64, email, role, password string) string {
	t.Helper()
	token := h.newInvitationForTest(t, orgID, email, role)
	w := h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": token, "password": password}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	return h.login(t, email, password)
}

type abResp struct {
	Code    gen.ErrorCode      `json:"code"`
	Message string             `json:"message"`
	Data    gen.AddressBook    `json:"data"`
	Errors  *gen.ErrorResponse `json:"-"`
}

func createBook(t *testing.T, h *harness, token string, orgID int64, name, scope string) *abResp {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/address-books",
		map[string]string{"name": name, "scope": scope}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var r abResp
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
	return &r
}

func TestAddressBook_CreatePersonal(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "ab-owner@example.com", "password123")
	ownerToken := h.login(t, "ab-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "ab-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	r := createBook(t, h, ownerToken, orgResp.Data.Id, "my-peers", "personal")
	require.Equal(t, gen.ErrorCodeOk, r.Code)
	require.Equal(t, "my-peers", r.Data.Name)
	require.Equal(t, gen.AddressBookScope("personal"), r.Data.Scope)
	require.NotNil(t, r.Data.OwnerId)
	require.NotZero(t, *r.Data.OwnerId)
	require.Equal(t, int64(0), r.Data.Revision)
}

func TestAddressBook_CreatePersonal_DuplicateName_409(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "ab-dup@example.com", "password123")
	ownerToken := h.login(t, "ab-dup@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "dup-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	createBook(t, h, ownerToken, orgResp.Data.Id, "same-name", "personal")
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/address-books",
		map[string]string{"name": "same-name", "scope": "personal"}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestAddressBook_CreateShared_MemberForbidden(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "ab-owner2@example.com", "password123")
	ownerToken := h.login(t, "ab-owner2@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "shared-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	memberToken := inviteAndJoin(t, h, orgResp.Data.Id, "plain2@example.com", "member", "memberpass1")

	// A member cannot create shared books.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/address-books",
		map[string]string{"name": "team-book", "scope": "shared"}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// The owner can.
	createBook(t, h, ownerToken, orgResp.Data.Id, "team-book", "shared")
}

func TestAddressBook_List_PersonalIsPrivate_SharedVisible(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "list-owner@example.com", "password123")
	ownerToken := h.login(t, "list-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "list-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := orgResp.Data.Id

	tokenA := inviteAndJoin(t, h, orgID, "member-a@example.com", "member", "memberpa1")
	tokenB := inviteAndJoin(t, h, orgID, "member-b@example.com", "member", "memberpb1")

	createBook(t, h, ownerToken, orgID, "team", "shared")
	createBook(t, h, tokenA, orgID, "a-personal", "personal")
	createBook(t, h, tokenB, orgID, "b-personal", "personal")

	// Member A sees: own personal + the shared book, not B's personal.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/address-books", nil, tokenA)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list struct {
		Data []gen.AddressBook `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list.Data, 2)
	names := map[string]bool{}
	for _, b := range list.Data {
		names[b.Name] = true
	}
	require.True(t, names["a-personal"], "own personal book must be listed")
	require.True(t, names["team"], "shared book must be listed")
	require.False(t, names["b-personal"], "another user's personal book must stay private")
}

func TestAddressBook_Get_PersonalOfOtherUser_404(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "get-owner@example.com", "password123")
	ownerToken := h.login(t, "get-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "get-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := orgResp.Data.Id

	tokenC := inviteAndJoin(t, h, orgID, "member-c@example.com", "member", "memberpc1")
	tokenD := inviteAndJoin(t, h, orgID, "member-d@example.com", "member", "memberpd1")

	created := createBook(t, h, tokenC, orgID, "c-private", "personal")

	// Member D cannot read C's personal book.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/address-books/"+itoa(created.Data.Id), nil, tokenD)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// C can.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/address-books/"+itoa(created.Data.Id), nil, tokenC)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestAddressBook_CrossOrgGet_404(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "xorg-a@example.com", "password123")
	h.seedUser(t, "xorg-b@example.com", "password123")
	tokenA := h.login(t, "xorg-a@example.com", "password123")
	tokenB := h.login(t, "xorg-b@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "xorg-a"}, tokenA)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgA struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgA))

	w = h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "xorg-b"}, tokenB)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgB struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgB))

	created := createBook(t, h, tokenA, orgA.Data.Id, "a-book", "personal")

	// Org B's owner must not see org A's book even with its id (Review Focus #1).
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgB.Data.Id)+"/address-books/"+itoa(created.Data.Id), nil, tokenB)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestAddressBook_UpdatePeers_RevisionIncrement(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "peers-owner@example.com", "password123")
	ownerToken := h.login(t, "peers-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "peers-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := orgResp.Data.Id

	created := createBook(t, h, ownerToken, orgID, "peers-book", "personal")
	bookPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(created.Data.Id)

	// Replace peers: two entries, one with tags.
	w = h.do(t, http.MethodPut, bookPath+"/peers", map[string]any{
		"peers": []map[string]any{
			{"peer_id": "111111", "alias": "alpha", "platform": "windows", "tags": []string{"infra"}},
			{"peer_id": "222222"},
		},
	}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var after1 abResp
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &after1))
	require.Equal(t, int64(1), after1.Data.Revision, "first replace must bump revision to 1")

	// GET returns the peers with their tags.
	w = h.do(t, http.MethodGet, bookPath, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got abResp
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.NotNil(t, got.Data.Peers)
	require.Len(t, *got.Data.Peers, 2)
	require.NotNil(t, (*got.Data.Peers)[0].Tags)
	require.Len(t, *(*got.Data.Peers)[0].Tags, 1)

	// A second replace bumps revision again and honours the new list.
	w = h.do(t, http.MethodPut, bookPath+"/peers", map[string]any{
		"peers": []map[string]any{{"peer_id": "333333"}},
	}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var after2 abResp
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &after2))
	require.Equal(t, int64(2), after2.Data.Revision, "second replace must bump revision to 2")
}

func TestAddressBook_ReplaceTags(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "tags-owner@example.com", "password123")
	ownerToken := h.login(t, "tags-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "tags-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := orgResp.Data.Id

	created := createBook(t, h, ownerToken, orgID, "tags-book", "personal")
	bookPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(created.Data.Id)

	w = h.do(t, http.MethodPut, bookPath+"/tags", map[string]any{
		"tags": []map[string]any{
			{"name": "infra", "color": 16711680},
			{"name": "dev"},
		},
	}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, bookPath, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got abResp
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.NotNil(t, got.Data.Tags)
	require.Len(t, *got.Data.Tags, 2)
	var infra *gen.AddressBookTag
	for i := range *got.Data.Tags {
		if (*got.Data.Tags)[i].Name == "infra" {
			infra = &(*got.Data.Tags)[i]
		}
	}
	require.NotNil(t, infra, "infra tag must be returned")
	require.NotNil(t, infra.Color)
	require.Equal(t, 16711680, *infra.Color)
}

func TestAddressBook_Delete_Cascades(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "del-owner@example.com", "password123")
	ownerToken := h.login(t, "del-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "del-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := orgResp.Data.Id

	created := createBook(t, h, ownerToken, orgID, "del-book", "personal")
	bookPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(created.Data.Id)

	// Seed a peer, then delete the book.
	w = h.do(t, http.MethodPut, bookPath+"/peers", map[string]any{
		"peers": []map[string]any{{"peer_id": "444444"}},
	}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code)

	w = h.do(t, http.MethodDelete, bookPath, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The book and its peers are gone.
	w = h.do(t, http.MethodGet, bookPath, nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code)

	var count int64
	require.NoError(t, h.db.DB.Unscoped().Raw(
		"SELECT count(*) FROM address_book_peers WHERE book_id = ?", created.Data.Id).Scan(&count).Error)
	require.Zero(t, count, "peers must be cascaded away with the book")
}

func TestAddressBook_UpdateName(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "upd-owner@example.com", "password123")
	ownerToken := h.login(t, "upd-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "upd-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := orgResp.Data.Id

	created := createBook(t, h, ownerToken, orgID, "old-name", "personal")
	bookPath := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(created.Data.Id)

	w = h.do(t, http.MethodPut, bookPath, map[string]string{"name": "new-name"}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var r abResp
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
	require.Equal(t, "new-name", r.Data.Name)
}
