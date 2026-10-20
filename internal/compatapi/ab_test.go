// Address book client sync tests (task 9). Payload shapes are frozen in
// testdata/ from the official client source: rustdesk master branch,
// flutter/lib/models/ab_model.dart + common/hbbs/hbbs.dart + models/
// peer_model.dart (fetched 2026-10-20; the plan requires pinning the client
// release once the Step 6 regression runs against the real 1.5 client).
package compatapi_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// abFixtureMap loads a fixture as a generic map (legacy envelopes, bodies).
func abFixtureMap(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

// The legacy whole-book flow: POST /api/ab replaces the personal book, then
// GET /api/ab returns the same content as the {"data": "<json string>"} the
// client's pullAbImpl expects, plus a 64-hex content hash. The Sciter-era
// /api/ab/get alias answers identically.
func TestABGet_MatchesFixture(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "ab@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)
	tok, _ := h.login(t, "ab@example.com", "password123", "777777770", "ab-uuid")

	// Empty book: the client treats a literal `null` body as empty.
	w := h.do(t, http.MethodGet, "/api/ab", nil, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "null", w.Body.String())

	// Push the frozen legacy payload (the client's pushAb body).
	post := abFixtureMap(t, "ab_legacy_post.json")
	w = h.do(t, http.MethodPost, "/api/ab", post, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Pull it back: the envelope matches the GET fixture structure.
	w = h.do(t, http.MethodGet, "/api/ab", nil, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	require.Contains(t, envelope, "data")
	require.Contains(t, envelope, "hash")
	require.Regexp(t, "^[0-9a-f]{64}$", envelope["hash"], "content hash is sha256 hex")

	// The data string decodes to the fixture content, including the peer's
	// opaque hash field round-trip.
	dataStr, _ := envelope["data"].(string)
	require.NotEmpty(t, dataStr)
	var content struct {
		Tags      []string         `json:"tags"`
		Peers     []map[string]any `json:"peers"`
		RawColors string           `json:"tag_colors"`
	}
	require.NoError(t, json.Unmarshal([]byte(dataStr), &content))
	var wantContent map[string]any
	wantData, _ := post["data"].(string)
	require.NoError(t, json.Unmarshal([]byte(wantData), &wantContent))
	require.ElementsMatch(t, wantContent["tags"], content.Tags)
	require.Len(t, content.Peers, 1)
	require.Equal(t, "1312211121", content.Peers[0]["id"])
	require.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		content.Peers[0]["hash"], "the peer hash must round-trip")
	require.Contains(t, content.RawColors, "ops")

	// The Sciter-era alias answers with the same envelope.
	w2 := h.do(t, http.MethodGet, "/api/ab/get", nil, tok)
	require.Equal(t, http.StatusOK, w2.Code, w2.Body.String())
	require.JSONEq(t, w.Body.String(), w2.Body.String())
}

// Review Focus #5: the legacy push is guarded by the content hash. A stale
// hash aborts with 409 ab_conflict; the correct hash replaces the book.
func TestABPost_ConflictDetection(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "conf@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)
	tok, _ := h.login(t, "conf@example.com", "password123", "777777771", "conf-uuid")

	post := abFixtureMap(t, "ab_legacy_post.json")
	w := h.do(t, http.MethodPost, "/api/ab", post, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, "/api/ab", nil, tok)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	currentHash, _ := envelope["hash"].(string)

	// A stale hash must not silently drop the other side's push.
	stale := abFixtureMap(t, "ab_legacy_post.json")
	stale["hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
	stale["data"] = "{\"tags\":[],\"peers\":[],\"tag_colors\":\"{}\"}"
	w = h.do(t, http.MethodPost, "/api/ab", stale, tok)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "ab_conflict")

	// The book keeps its content after the rejected push.
	w = h.do(t, http.MethodGet, "/api/ab", nil, tok)
	var after map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &after))
	require.Equal(t, envelope["data"], after["data"])

	// The correct hash replaces the book.
	w = h.do(t, http.MethodPost, "/api/ab", map[string]any{
		"data": "{\"tags\":[],\"peers\":[],\"tag_colors\":\"{}\"}",
		"hash": currentHash,
	}, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/ab", nil, tok)
	var replaced map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &replaced))
	replacedData, _ := replaced["data"].(string)
	require.JSONEq(t, "{\"tags\":[],\"peers\":[],\"tag_colors\":\"{}\"}", replacedData)
}

// C14/C16 isolation: the personal book is per organization. A session bound
// to org B sees an empty book even though the same user has content in org
// A, and org A's guid does not resolve from the org B session.
func TestABPersonal_CrossOrgEmpty(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "multi@example.com", "password123", true)
	orgA := h.seedOrg(t, "org-a")
	orgB := h.seedOrg(t, "org-b")
	h.seedMembership(t, u.ID, orgA.ID)
	h.seedMembership(t, u.ID, orgB.ID)

	// Org A session: push content.
	tokA, _ := h.login(t, "multi@example.com#"+strconv.FormatUint(uint64(orgA.ID), 10),
		"password123", "777777772", "ab-uuid-a")
	post := abFixtureMap(t, "ab_legacy_post.json")
	w := h.do(t, http.MethodPost, "/api/ab", post, tokA)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Org A's personal guid for the cross-session probe below.
	w = h.do(t, http.MethodPost, "/api/ab/personal", nil, tokA)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var guidA map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &guidA))
	guidAStr, _ := guidA["guid"].(string)
	require.NotEmpty(t, guidAStr)

	// Org B session: the book does not exist yet — the legacy GET answers
	// literal null (the client clears its copy) before any probe creates it.
	tokB, _ := h.login(t, "multi@example.com#"+strconv.FormatUint(uint64(orgB.ID), 10),
		"password123", "777777773", "ab-uuid-b")
	w = h.do(t, http.MethodGet, "/api/ab", nil, tokB)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "null", w.Body.String(), "org B must not see org A content")

	// The personal probe then creates org B's own empty book.
	w = h.do(t, http.MethodPost, "/api/ab/personal", nil, tokB)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var guidB map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &guidB))
	guidBStr, _ := guidB["guid"].(string)
	require.NotEmpty(t, guidBStr)
	require.NotEqual(t, guidAStr, guidBStr, "each organization has its own book")

	// Org A's guid does not resolve from the org B session, both on the
	// paged fetch and the granular mutations.
	w = h.do(t, http.MethodPost, "/api/ab/peers?current=1&pageSize=100&ab="+guidAStr, nil, tokB)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/peer/add/"+guidAStr,
		abFixtureMap(t, "ab_peer_add.json"), tokB)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// The granular 1.4+ flow: personal guid, paged peers, one-peer add/update/
// delete and tag add/rename/update/delete, all scoped to the personal book
// of the session's organization.
func TestABGranularFlow(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "gran@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)
	tok, _ := h.login(t, "gran@example.com", "password123", "777777774", "gran-uuid")

	// Mode probe: the client treats 200 + guid as new mode.
	w := h.do(t, http.MethodPost, "/api/ab/personal", nil, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var personal map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &personal))
	guid, _ := personal["guid"].(string)
	require.NotEmpty(t, guid)
	w2 := h.do(t, http.MethodPost, "/api/ab/personal", nil, tok)
	var personal2 map[string]any
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &personal2))
	require.Equal(t, guid, personal2["guid"], "the guid is stable across calls")

	// Peer add: the fixture body carries the client's Peer.toCustomJson
	// fields including the opaque hash.
	w = h.do(t, http.MethodPost, "/api/ab/peer/add/"+guid,
		abFixtureMap(t, "ab_peer_add.json"), tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Paged peers: shape matches the fixture, hash preserved.
	w = h.do(t, http.MethodPost, "/api/ab/peers?current=1&pageSize=100&ab="+guid, nil, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page struct {
		Total int              `json:"total"`
		Data  []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.EqualValues(t, 1, page.Total)
	require.Len(t, page.Data, 1)
	require.Equal(t, "1412222122", page.Data[0]["id"])
	require.Equal(t, "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		page.Data[0]["hash"])

	// Tag add, then the tag list matches the fixture.
	w = h.do(t, http.MethodPost, "/api/ab/tag/add/"+guid,
		abFixtureMap(t, "ab_tag_add.json"), tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/tags/"+guid, nil, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tags []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tags))
	wantTags := abFixtureList(t, "ab_tags_list.json")
	require.Len(t, tags, len(wantTags))
	require.Equal(t, wantTags[0]["name"], tags[0]["name"])
	require.EqualValues(t, wantTags[0]["color"], tags[0]["color"])

	// Partial peer update: alias/note/hash change, id and others stay.
	w = h.do(t, http.MethodPut, "/api/ab/peer/update/"+guid,
		abFixtureMap(t, "ab_peer_update.json"), tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/peers?current=1&pageSize=100&ab="+guid, nil, tok)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Equal(t, "bob-main", page.Data[0]["alias"])
	require.Equal(t, "front desk", page.Data[0]["note"])
	require.Equal(t, "aa", page.Data[0]["hash"])
	require.Equal(t, "carol", page.Data[0]["username"], "unmentioned fields stay")

	// Tag rename cascades into the peer's tag list.
	w = h.do(t, http.MethodPut, "/api/ab/tag/rename/"+guid,
		abFixtureMap(t, "ab_tag_rename.json"), tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/peers?current=1&pageSize=100&ab="+guid, nil, tok)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Equal(t, []any{"dev"}, page.Data[0]["tags"])

	// Tag color update, then tag delete empties both the list and the
	// peers' tag references.
	w = h.do(t, http.MethodPut, "/api/ab/tag/update/"+guid,
		map[string]any{"name": "dev", "color": 123}, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, "/api/ab/tag/"+guid, []string{"dev"}, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/tags/"+guid, nil, tok)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "[]", w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/peers?current=1&pageSize=100&ab="+guid, nil, tok)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Equal(t, []any{}, page.Data[0]["tags"])

	// Peer delete clears the book.
	w = h.do(t, http.MethodDelete, "/api/ab/peer/"+guid, []string{"1412222122"}, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/peers?current=1&pageSize=100&ab="+guid, nil, tok)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Zero(t, page.Total)
}

// The legacy sciter alias is reachable and identical when the book has
// content: /api/ab/get answers the same envelope as /api/ab.
func TestABLegacy_SciterCompat(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "sciter@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)
	tok, _ := h.login(t, "sciter@example.com", "password123", "777777775", "sciter-uuid")

	post := abFixtureMap(t, "ab_legacy_post.json")
	w := h.do(t, http.MethodPost, "/api/ab", post, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	wMain := h.do(t, http.MethodGet, "/api/ab", nil, tok)
	wAlias := h.do(t, http.MethodGet, "/api/ab/get", nil, tok)
	require.Equal(t, wMain.Code, wAlias.Code)
	require.JSONEq(t, wMain.Body.String(), wAlias.Body.String())

	// Both endpoints land in the same personal book (one row only).
	var books int64
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Model(&model.AddressBook{}).Count(&books).Error)
	require.EqualValues(t, 1, books)
}

// abFixtureList loads a fixture as a generic list (tags list).
func abFixtureList(t *testing.T, name string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var l []map[string]any
	require.NoError(t, json.Unmarshal(b, &l))
	return l
}

// A huge `current` must not overflow the offset multiplication into a
// negative slice index (runtime panic): out-of-range pages answer 200 with
// an empty page.
func TestABPeersPage_OverflowCurrentIsSafe(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "page@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)
	tok, _ := h.login(t, "page@example.com", "password123", "777777776", "page-uuid")

	w := h.do(t, http.MethodPost, "/api/ab/personal", nil, tok)
	var personal map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &personal))
	guid, _ := personal["guid"].(string)

	w = h.do(t, http.MethodPost,
		"/api/ab/peers?current=36893488147419104&pageSize=500&ab="+guid, nil, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page struct {
		Total int              `json:"total"`
		Data  []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Zero(t, page.Total)
	require.Empty(t, page.Data)
}

// The compat layer maps onto the user's personal book only: a shared book's
// guid must not resolve through any compat endpoint (CWE-639).
func TestABCompat_SharedBookUnreachable(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "shared@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)
	tok, _ := h.login(t, "shared@example.com", "password123", "777777777", "shared-uuid")

	// A shared book of the same organization (visible to members through
	// the management API, never through the compat dialect).
	shared := model.AddressBook{
		OrganizationID: org.ID,
		Scope:          model.AddressBookScopeShared,
		Name:           "Team Book",
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Create(&shared).Error)
	guid := strconv.FormatUint(uint64(shared.ID), 10)

	w := h.do(t, http.MethodPost, "/api/ab/peers?current=1&pageSize=100&ab="+guid, nil, tok)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/peer/add/"+guid,
		abFixtureMap(t, "ab_peer_add.json"), tok)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/ab/tags/"+guid, nil, tok)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// A storage fault during the book lookup must surface as 500 "address book
// lookup failed", not 404 — operations have to be able to tell a missing
// book from a service failure.
func TestABLookup_DBFailureIs500(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "fault@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)
	tok, _ := h.login(t, "fault@example.com", "password123", "777777778", "fault-uuid")

	// The book exists (so the book row query succeeds) and then the peers
	// table is dropped to simulate a storage fault under it.
	w := h.do(t, http.MethodPost, "/api/ab/personal", nil, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var personal map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &personal))
	guid, _ := personal["guid"].(string)
	require.NotEmpty(t, guid)

	require.NoError(t, h.db.DB.Exec("DROP TABLE address_book_peers").Error)

	w = h.do(t, http.MethodPost, "/api/ab/peers?current=1&pageSize=100&ab="+guid, nil, tok)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "address book lookup failed")

	w = h.do(t, http.MethodPost, "/api/ab/tags/"+guid, nil, tok)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "address book lookup failed")

	w = h.do(t, http.MethodPost, "/api/ab/peer/add/"+guid,
		abFixtureMap(t, "ab_peer_add.json"), tok)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "address book lookup failed")
}
