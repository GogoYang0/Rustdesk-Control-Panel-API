package captcha

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func geetestProof(fields map[string]string) Proof {
	return Proof{Response: fields}
}

func TestGeeTest_RequestShape(t *testing.T) {
	var gotQuery, gotForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotQuery = r.URL.RawQuery
		gotForm = r.PostForm.Encode()
		_, _ = w.Write([]byte(`{"status":"success","result":"success"}`))
	}))
	defer srv.Close()

	p := newGeetestProvider("captcha-id", "secret-key", srv.URL, srv.Client())
	err := p.Verify(context.Background(), geetestProof(map[string]string{
		"lot_number":     "lot-1",
		"captcha_output": "out-1",
		"pass_token":     "pass-1",
		"gen_time":       "1700000000",
	}))
	require.NoError(t, err)

	require.Contains(t, gotQuery, "captcha_id=captcha-id")
	require.Contains(t, gotForm, "lot_number=lot-1")
	require.Contains(t, gotForm, "captcha_output=out-1")
	require.Contains(t, gotForm, "pass_token=pass-1")
	require.Contains(t, gotForm, "gen_time=1700000000")

	mac := hmac.New(sha256.New, []byte("secret-key"))
	mac.Write([]byte("lot-1"))
	require.Contains(t, gotForm, "sign_token="+hex.EncodeToString(mac.Sum(nil)))
}

func TestGeeTest_ProviderErrorIsInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","result":"fail","reason":"invalid signature"}`))
	}))
	defer srv.Close()

	p := newGeetestProvider("captcha-id", "secret-key", srv.URL, srv.Client())
	// Even with fail-mode open, a provider judgement must never pass.
	s := NewService(p, ServiceOptions{FailMode: "open"})
	require.ErrorIs(t, s.Verify(context.Background(), geetestProof(map[string]string{
		"lot_number": "lot-1", "captcha_output": "out", "pass_token": "pass", "gen_time": "1",
	})), ErrInvalid)
}

func TestGeeTest_ResultFailIsInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","result":"fail"}`))
	}))
	defer srv.Close()

	p := newGeetestProvider("captcha-id", "secret-key", srv.URL, srv.Client())
	require.ErrorIs(t, p.Verify(context.Background(), geetestProof(map[string]string{
		"lot_number": "lot-1", "captcha_output": "out", "pass_token": "pass", "gen_time": "1",
	})), ErrInvalid)
}

func TestGeeTest_TransportFailureIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	p := newGeetestProvider("captcha-id", "secret-key", srv.URL, srv.Client())
	proof := geetestProof(map[string]string{
		"lot_number": "lot-1", "captcha_output": "out", "pass_token": "pass", "gen_time": "1",
	})

	require.ErrorIs(t, NewService(p, ServiceOptions{FailMode: "closed"}).Verify(context.Background(), proof), ErrUnavailable)
	require.NoError(t, NewService(p, ServiceOptions{FailMode: "open"}).Verify(context.Background(), proof))
}

func TestGeeTest_MissingFields(t *testing.T) {
	p := newGeetestProvider("captcha-id", "secret-key", "https://unused.invalid", http.DefaultClient)
	require.ErrorIs(t, p.Verify(context.Background(), geetestProof(map[string]string{"lot_number": "x"})), ErrInvalid)
}

func TestGeeTest_ChallengeParams(t *testing.T) {
	p := newGeetestProvider("captcha-id", "secret-key", "https://unused.invalid", http.DefaultClient)
	ch, err := p.Challenge(context.Background())
	require.NoError(t, err)
	require.Equal(t, "geetest", ch.Provider)
	require.Equal(t, "captcha-id", ch.Params["captcha_id"])
	require.Equal(t, "https://static.geetest.com/v4/gt4.js", ch.Params["script_url"])
}

func TestGeeTest_ResponseDecodeErrorIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := newGeetestProvider("captcha-id", "secret-key", srv.URL, srv.Client())
	require.ErrorIs(t, p.Verify(context.Background(), geetestProof(map[string]string{
		"lot_number": "lot-1", "captcha_output": "out", "pass_token": "pass", "gen_time": "1",
	})), ErrUnavailable)
}
