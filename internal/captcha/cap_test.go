package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func capProof(token string) Proof {
	return Proof{Response: map[string]string{"response": token}}
}

func TestCap_Siteverify(t *testing.T) {
	var gotPath string
	var body struct {
		Secret   string `json:"secret"`
		Response string `json:"response"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	p := newCapProvider(srv.URL+"/", "site-key", "cap-secret", srv.Client())
	require.NoError(t, p.Verify(context.Background(), capProof("token-1")))

	require.Equal(t, "/site-key/siteverify", gotPath)
	require.Equal(t, "cap-secret", body.Secret)
	require.Equal(t, "token-1", body.Response)
}

func TestCap_ProviderErrorIsInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false}`))
	}))
	defer srv.Close()

	p := newCapProvider(srv.URL, "site-key", "cap-secret", srv.Client())
	// Fail-mode open must not turn a judgement into a pass.
	s := NewService(p, ServiceOptions{FailMode: "open"})
	require.ErrorIs(t, s.Verify(context.Background(), capProof("token-1")), ErrInvalid)
}

func TestCap_TransportFailureIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	p := newCapProvider(srv.URL, "site-key", "cap-secret", srv.Client())
	require.ErrorIs(t, NewService(p, ServiceOptions{FailMode: "closed"}).Verify(context.Background(), capProof("t")), ErrUnavailable)
	require.NoError(t, NewService(p, ServiceOptions{FailMode: "open"}).Verify(context.Background(), capProof("t")))
}

// Cap answers a missing or already consumed token with 404 (and an expired one
// with 403) plus {"success":false}: that is a judgement, so fail-mode open must
// not turn the rejection into an admission.
func TestCap_RejectionStatusIsInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"error":"Token not found"}`))
	}))
	defer srv.Close()

	p := newCapProvider(srv.URL, "site-key", "cap-secret", srv.Client())
	require.ErrorIs(t, NewService(p, ServiceOptions{FailMode: "closed"}).Verify(context.Background(), capProof("t-closed")), ErrInvalid)
	require.ErrorIs(t, NewService(p, ServiceOptions{FailMode: "open"}).Verify(context.Background(), capProof("t-open")), ErrInvalid)
}

// A body without a success field carries no verdict - an intermediary error
// page, for instance - and stays an outage rather than becoming a judgement.
func TestCap_BodyWithoutVerdictIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer srv.Close()

	p := newCapProvider(srv.URL, "site-key", "cap-secret", srv.Client())
	require.ErrorIs(t, NewService(p, ServiceOptions{FailMode: "closed"}).Verify(context.Background(), capProof("t")), ErrUnavailable)
}

func TestCap_MissingToken(t *testing.T) {
	p := newCapProvider("https://unused.invalid", "site-key", "cap-secret", http.DefaultClient)
	require.ErrorIs(t, p.Verify(context.Background(), Proof{}), ErrRequired)
}

func TestCap_ChallengeParams(t *testing.T) {
	p := newCapProvider("https://cap.example.com/", "site-key", "cap-secret", http.DefaultClient)
	ch, err := p.Challenge(context.Background())
	require.NoError(t, err)
	require.Equal(t, "cap", ch.Provider)
	// The Cap widget appends challenge/redeem to the endpoint, so the trailing
	// slash is required.
	require.Equal(t, "https://cap.example.com/site-key/", ch.Params["api_endpoint"])
	require.Equal(t, "site-key", ch.Params["site_key"])
}

func TestCap_TokenIsSingleUse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	p := newCapProvider(srv.URL, "site-key", "cap-secret", srv.Client())
	require.NoError(t, p.Verify(context.Background(), capProof("token-1")))
	require.ErrorIs(t, p.Verify(context.Background(), capProof("token-1")), ErrInvalid)
}
