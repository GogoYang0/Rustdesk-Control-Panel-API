package main

import "testing"

// The origin check only fires in production mail mode, where every link
// embeds a plaintext token: any loopback, private or malformed origin must
// be rejected at startup instead of silently shipping dead links.
func TestIsPublicHTTPSOrigin(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://panel.example.com", true},
		{"https://panel.example.com:8443", true},

		{"http://panel.example.com", false},       // not https
		{"https://localhost", false},              // loopback name
		{"https://sub.localhost", false},          // loopback suffix
		{"https://127.0.0.1", false},              // loopback IPv4
		{"https://[::1]:8443", false},             // loopback IPv6
		{"https://192.168.1.10", false},           // private IPv4
		{"https://10.0.0.5", false},               // private IPv4
		{"https://[fd00::1]", false},              // private IPv6
		{"https://panel.example.com/app", false},  // path
		{"https://panel.example.com?x=1", false},  // query
		{"https://user@panel.example.com", false}, // userinfo
		{"", false},          // empty
		{"not a url", false}, // unparseable scheme
	}

	for _, tc := range cases {
		if got := isPublicHTTPSOrigin(tc.raw); got != tc.want {
			t.Errorf("isPublicHTTPSOrigin(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
