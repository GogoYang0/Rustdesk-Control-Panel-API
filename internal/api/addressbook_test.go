package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// inviteAndJoin creates an invitation directly and joins the user, returning
// their bearer token.
func inviteAndJoin(t *testing.T, h *harness, orgID int64, email, role, password string) string {
	t.Helper()
	token := h.newInvitationForTest(t, orgID, email, role)
	w := h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": token, "password": password}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// The join flow now starts the account unverified (issue #17); these
	// tests only need an established member, so confirm the mailbox
	// directly instead of walking the verification mail round-trip.
	require.NoError(t, h.db.DB.Model(&model.User{}).
		Where("email = ?", email).
		Update("email_verified", true).Error)
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

// seedOrgOwner creates a user plus a fresh org, returning the bearer token
// and org id.
func seedOrgOwner(t *testing.T, h *harness, email string) (string, int64) {
	t.Helper()
	h.seedUser(t, email, "password123")
	token := h.login(t, email, "password123")
	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "org-" + email}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var org struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &org))
	return token, org.Data.Id
}

// Review fix 1: Update must reject a rename that collides with another book
// in the same org+scope (shared books have NULL owner, so the unique index
// alone does not deduplicate them).
func TestAddressBook_Update_DuplicateName(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "dup6@example.com")

	createBook(t, h, token, orgID, "shared-one", "shared")
	second := createBook(t, h, token, orgID, "shared-two", "shared")

	// Renaming shared-two to shared-one must conflict.
	w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/address-books/"+itoa(second.Data.Id),
		map[string]string{"name": "shared-one"}, token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

// Review fix 3: invalid replace payloads must be 400, not a 500 from a
// violated unique index.
func TestAddressBook_ReplacePeers_InvalidInput(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "dup7@example.com")
	book := createBook(t, h, token, orgID, "peers-validate", "personal")
	path := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(book.Data.Id) + "/peers"

	cases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "duplicate peer ids",
			body: map[string]any{"peers": []map[string]any{
				{"peer_id": "111111"}, {"peer_id": "111111"},
			}},
		},
		{
			name: "empty peer id",
			body: map[string]any{"peers": []map[string]any{{"peer_id": ""}}},
		},
		{
			name: "overlong peer id",
			body: map[string]any{"peers": []map[string]any{{"peer_id": strings.Repeat("x", 65)}}},
		},
	}
	for _, tc := range cases {
		w := h.do(t, http.MethodPut, path, tc.body, token)
		require.Equal(t, http.StatusBadRequest, w.Code, tc.name+": "+w.Body.String())
	}
}

func TestAddressBook_ReplaceTags_InvalidInput(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "dup8@example.com")
	book := createBook(t, h, token, orgID, "tags-validate", "personal")
	path := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(book.Data.Id) + "/tags"

	cases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "duplicate tag names",
			body: map[string]any{"tags": []map[string]any{
				{"name": "dup", "color": 1}, {"name": "dup", "color": 2},
			}},
		},
		{
			name: "empty tag name",
			body: map[string]any{"tags": []map[string]any{{"name": "", "color": 1}}},
		},
	}
	for _, tc := range cases {
		w := h.do(t, http.MethodPut, path, tc.body, token)
		require.Equal(t, http.StatusBadRequest, w.Code, tc.name+": "+w.Body.String())
	}
}

// Review fix 2: concurrent full-replaces must serialise on the book row —
// every response is a complete list (never a merged one).
func TestAddressBook_ReplacePeers_ConcurrentSerialised(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "dup9@example.com")
	book := createBook(t, h, token, orgID, "concurrent", "personal")
	path := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(book.Data.Id) + "/peers"

	var wg sync.WaitGroup
	errCh := make(chan int, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			w := h.do(t, http.MethodPut, path, map[string]any{
				"peers": []map[string]any{{"peer_id": itoa(int64(n))}},
			}, token)
			if w.Code != http.StatusOK {
				errCh <- w.Code
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for code := range errCh {
		t.Fatalf("concurrent replace returned %d", code)
	}

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/address-books/"+itoa(book.Data.Id), nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got abResp
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.NotNil(t, got.Data.Peers)
	require.Len(t, *got.Data.Peers, 1, "final peer list must be one complete replace, not a merge")
}

// Review round 2: length checks count Unicode characters, not bytes —
// varchar(64) in PostgreSQL/MySQL is 64 characters, so a 22-character
// Chinese tag name is legal and must not be rejected.
func TestAddressBook_ReplaceTags_UnicodeNamesAccepted(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "uni1@example.com")
	book := createBook(t, h, token, orgID, "uni-tags", "personal")
	path := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(book.Data.Id) + "/tags"

	name := strings.Repeat("标", 22) // 22 chars, 66 bytes
	w := h.do(t, http.MethodPut, path, map[string]any{
		"tags": []map[string]any{{"name": name, "color": 16711680}},
	}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/address-books/"+itoa(book.Data.Id), nil, token)
	var got abResp
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.NotNil(t, got.Data.Tags)
	require.Len(t, *got.Data.Tags, 1)
	require.Equal(t, name, (*got.Data.Tags)[0].Name)
}

// Review round 2: the remaining length-bounded columns must reject overlong
// input with 400 instead of a varchar error mid-transaction (500).
func TestAddressBook_ReplacePeers_FieldOverlong(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "uni2@example.com")
	book := createBook(t, h, token, orgID, "uni-peers", "personal")
	path := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(book.Data.Id) + "/peers"

	cases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "alias over 128 chars",
			body: map[string]any{"peers": []map[string]any{
				{"peer_id": "111111", "alias": strings.Repeat("a", 129)},
			}},
		},
		{
			name: "platform over 64 chars",
			body: map[string]any{"peers": []map[string]any{
				{"peer_id": "111111", "platform": strings.Repeat("w", 65)},
			}},
		},
		{
			name: "overlong unicode alias (129 chars, 387 bytes)",
			body: map[string]any{"peers": []map[string]any{
				{"peer_id": "111111", "alias": strings.Repeat("别", 129)},
			}},
		},
		{
			name: "tags json encoding over 2048 bytes",
			body: map[string]any{"peers": []map[string]any{
				{
					"peer_id": "111111",
					// 40 tags x 60 chars each: far beyond the 2048-char TagsJSON column.
					"tags": func() []string {
						tags := make([]string, 40)
						for i := range tags {
							tags[i] = strings.Repeat("t", 60)
						}
						return tags
					}(),
				},
			}},
		},
	}
	for _, tc := range cases {
		w := h.do(t, http.MethodPut, path, tc.body, token)
		require.Equal(t, http.StatusBadRequest, w.Code, tc.name+": "+w.Body.String())
	}
}

// Review round 2: concurrent creation of same-named shared books must yield
// exactly one success — the pre-check alone cannot prevent that, so Create
// serialises on the organization row.
func TestAddressBook_Create_ConcurrentSharedDuplicate(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "uni3@example.com")

	var mu sync.Mutex
	created := 0
	conflicted := 0
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/address-books",
				map[string]string{"name": "race-shared", "scope": "shared"}, token)
			mu.Lock()
			defer mu.Unlock()
			switch w.Code {
			case http.StatusCreated:
				created++
			case http.StatusConflict:
				conflicted++
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 1, created, "exactly one create must succeed")
	require.Equal(t, 5, conflicted, "the other five must conflict")
}

// Review round 2: book names are varchar(128) — overlong names must be 400.
func TestAddressBook_Create_NameOverlong(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "uni4@example.com")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/address-books",
		map[string]string{"name": strings.Repeat("n", 129), "scope": "personal"}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

// Review round 3 (outside diff): Update's duplicate check and the rename
// must share Create's organization-row lock, otherwise a concurrent Create
// can insert the target name between the check and the write.
func TestAddressBook_Update_Create_ConcurrentNoDuplicates(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "uni5@example.com")
	book := createBook(t, h, token, orgID, "renamed-src", "shared")

	// On SQLite the in-memory database serialises writers and can answer
	// concurrent contention with 500s, so exact per-status counts are not
	// assertable here. The invariants that must hold on every backend: at
	// most one successful creation of the same name; renames to an existing
	// name are idempotent no-ops (200 is legal for every loser); and the
	// final state contains no duplicate names.
	var mu sync.Mutex
	created, updated := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/address-books",
				map[string]string{"name": "race-target", "scope": "shared"}, token)
			mu.Lock()
			defer mu.Unlock()
			if w.Code == http.StatusCreated {
				created++
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/address-books/"+itoa(book.Data.Id),
				map[string]string{"name": "race-target"}, token)
			mu.Lock()
			defer mu.Unlock()
			if w.Code == http.StatusOK {
				updated++
			}
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, created, 1, "duplicate shared name must not be created twice")
	require.Greater(t, created+updated, 0, "at least one concurrent write must succeed")

	// Final state: no two same-named shared books.
	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/address-books", nil, token)
	require.Equal(t, http.StatusOK, w.Code)
	var list struct {
		Data []gen.AddressBook `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	names := map[string]int{}
	for _, b := range list.Data {
		names[b.Name]++
	}
	for name, n := range names {
		require.LessOrEqual(t, n, 1, "duplicate shared book name after race: "+name)
	}
}

// Review round 4: a rename racing a delete must never report success for a
// deleted book — the rename re-reads the row under the book lock inside the
// transaction and maps a vanished row to 404.
func TestAddressBook_Update_Delete_Race(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "uni6@example.com")
	book := createBook(t, h, token, orgID, "race-del", "shared")
	path := "/api/v1/orgs/" + itoa(orgID) + "/address-books/" + itoa(book.Data.Id)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := h.do(t, http.MethodPut, path, map[string]string{"name": "race-del-renamed"}, token)
			mu := w.Code
			if mu != http.StatusOK && mu != http.StatusNotFound && mu != http.StatusConflict {
				t.Errorf("rename returned %d: %s", w.Code, w.Body.String())
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.do(t, http.MethodDelete, path, nil, token)
		}()
	}
	wg.Wait()

	w := h.do(t, http.MethodGet, path, nil, token)
	if w.Code == http.StatusOK {
		var got abResp
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		require.Equal(t, "race-del-renamed", got.Data.Name,
			"a surviving book must carry the renamed value exactly once")
	}
}
