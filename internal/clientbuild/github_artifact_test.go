package clientbuild

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostAllowed(t *testing.T) {
	patterns := []string{"github.com", "*.blob.core.windows.net"}
	require.True(t, hostAllowed("github.com", patterns))
	require.False(t, hostAllowed("foo.github.com", patterns))
	require.True(t, hostAllowed("foo.blob.core.windows.net", patterns))
	require.True(t, hostAllowed("FOO.BLOB.CORE.WINDOWS.NET.", patterns))
	require.False(t, hostAllowed("evil.example.com", patterns))
	require.True(t, hostAllowed("foo.github.com", []string{"*.github.com"}))
}

func TestValidateArtifactURL(t *testing.T) {
	patterns := []string{"github.com", "*.blob.core.windows.net"}
	u, err := validateArtifactURL("https://foo.blob.core.windows.net/a.zip?sv=1", patterns)
	require.NoError(t, err)
	require.Equal(t, "foo.blob.core.windows.net", u.Hostname())
	for _, raw := range []string{
		"http://foo.blob.core.windows.net/a.zip",
		"https://user@foo.blob.core.windows.net/a.zip",
		"https://127.0.0.1/a.zip",
		"https://foo.blob.core.windows.net:8443/a.zip",
		"https://evil.example.com/a.zip",
	} {
		_, err := validateArtifactURL(raw, patterns)
		require.Errorf(t, err, "URL %q must be rejected", raw)
		require.NotContains(t, err.Error(), "sv=")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func publicLookup(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

func TestArtifactFetcher_NoAuthAndLimit(t *testing.T) {
	var gotAuth string
	var gotURL string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		gotURL = r.URL.String()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("123456")),
			Header:     make(http.Header),
		}, nil
	})}
	f := &artifactFetcher{
		hosts: []string{"*.blob.core.windows.net"}, client: client, lookupIP: publicLookup,
	}
	dest := filepath.Join(t.TempDir(), "a.zip")
	_, err := f.fetch(context.Background(), "https://foo.blob.core.windows.net/a.zip?sv=secret", dest, 5)
	require.Error(t, err)
	require.Equal(t, "", gotAuth)
	require.Contains(t, gotURL, "foo.blob.core.windows.net")
	require.NoFileExists(t, dest)

	// A second run within the limit succeeds.
	_, err = f.fetch(context.Background(), "https://foo.blob.core.windows.net/a.zip", dest, 10)
	require.NoError(t, err)
	raw, err := os.ReadFile(dest)
	require.NoError(t, err)
	require.Equal(t, "123456", string(raw))
}

func TestArtifactFetcher_RejectsPrivateLookup(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("x"))}, nil
	})}
	f := &artifactFetcher{
		hosts: []string{"*.blob.core.windows.net"}, client: client,
		lookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		},
	}
	_, err := f.fetch(context.Background(), "https://foo.blob.core.windows.net/a.zip",
		filepath.Join(t.TempDir(), "a.zip"), 10)
	require.Error(t, err)
	require.False(t, called)
}

func TestArtifactFetcher_RejectsUnlistedRedirect(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://evil.example.com/a.zip"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})}
	f := &artifactFetcher{
		hosts: []string{"*.blob.core.windows.net"}, client: client, lookupIP: publicLookup,
	}
	_, err := f.fetch(context.Background(), "https://foo.blob.core.windows.net/a.zip",
		filepath.Join(t.TempDir(), "a.zip"), 10)
	require.Error(t, err)
}
