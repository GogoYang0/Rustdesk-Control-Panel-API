package clientbuild

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func hostAllowed(host string, patterns []string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	for _, pattern := range patterns {
		p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
		if strings.HasPrefix(p, "*.") {
			suffix := p[2:]
			if suffix != "" && (host == suffix || strings.HasSuffix(host, "."+suffix)) {
				return true
			}
			continue
		}
		if host == p {
			return true
		}
	}
	return false
}

func validateArtifactURL(raw string, patterns []string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("artifact URL is invalid")
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("artifact URL must use https")
	}
	if u.User != nil {
		return nil, fmt.Errorf("artifact URL must not contain userinfo")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("artifact URL has no host")
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, fmt.Errorf("artifact URL must use port 443")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || net.ParseIP(host) != nil {
		return nil, fmt.Errorf("artifact URL host is not a DNS name")
	}
	if !hostAllowed(host, patterns) {
		return nil, fmt.Errorf("artifact URL host is not allowed")
	}
	return u, nil
}

type artifactFetcher struct {
	hosts    []string
	client   *http.Client
	lookupIP func(context.Context, string) ([]net.IP, error)
}

func newArtifactFetcher(hosts []string) *artifactFetcher {
	return &artifactFetcher{
		hosts: hosts,
		lookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
	}
}

func (f *artifactFetcher) fetch(ctx context.Context, location, destPath string, maxBytes int64) (int64, error) {
	if maxBytes <= 0 {
		return 0, fmt.Errorf("artifact download size limit is required")
	}
	u, err := validateArtifactURL(location, f.hosts)
	if err != nil {
		return 0, err
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	ips, err := f.lookupIP(ctx, host)
	if err != nil {
		return 0, fmt.Errorf("resolve artifact host: %w", err)
	}
	public := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return 0, fmt.Errorf("artifact host resolves to a non-public address")
		}
		public = append(public, ip)
	}
	if len(public) == 0 {
		return 0, fmt.Errorf("artifact host has no public address")
	}

	client := f.client
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Minute,
			Transport: &http.Transport{
				DialContext: (&safeDialer{lookupIP: f.lookupIP}).DialContext,
			},
		}
	}
	copied := *client
	copied.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("artifact redirect limit exceeded")
		}
		if _, err := validateArtifactURL(req.URL.String(), f.hosts); err != nil {
			return err
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("build artifact request")
	}
	req.Header.Set("User-Agent", "rustdesk-control-panel")
	resp, err := copied.Do(req)
	if err != nil {
		return 0, fmt.Errorf("artifact download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("artifact download failed with status %d", resp.StatusCode)
	}
	return writeLimited(resp.Body, destPath, maxBytes)
}

type safeDialer struct {
	lookupIP func(context.Context, string) ([]net.IP, error)
}

func (d *safeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := d.lookupIP(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			continue
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	return nil, fmt.Errorf("artifact host has no public address")
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() && !ip.IsUnspecified()
}

func writeLimited(body io.Reader, destPath string, maxBytes int64) (int64, error) {
	dir := filepath.Dir(destPath)
	tmp, err := os.CreateTemp(dir, ".artifact-*")
	if err != nil {
		return 0, err
	}
	name := tmp.Name()
	cleanup := func() {
		tmp.Close()
		_ = os.Remove(name)
	}
	n, err := io.Copy(tmp, io.LimitReader(body, maxBytes+1))
	if err != nil {
		cleanup()
		return 0, fmt.Errorf("write artifact: %w", err)
	}
	if n > maxBytes {
		cleanup()
		return 0, fmt.Errorf("artifact exceeds the configured size limit")
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return 0, err
	}
	if err := os.Rename(name, destPath); err != nil {
		_ = os.Remove(name)
		return 0, err
	}
	return n, nil
}
