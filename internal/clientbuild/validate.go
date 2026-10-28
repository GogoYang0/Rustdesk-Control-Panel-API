package clientbuild

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image/png"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Logo struct {
	PNG    []byte
	SHA256 string
	Width  int
	Height int
}

var serverKeyPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{16,128}={0,2}$`)

func ValidateProfileName(raw string) (name, key string, err error) {
	name = strings.TrimSpace(raw)
	if n := utf8.RuneCountInString(name); n < 1 || n > 64 {
		return "", "", fmt.Errorf("%w: profile name must be 1-64 characters", ErrInvalidInput)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", "", fmt.Errorf("%w: profile name contains a control character", ErrInvalidInput)
		}
	}
	return name, strings.ToLower(name), nil
}

func ValidateAppName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if n := utf8.RuneCountInString(name); n < 1 || n > 32 {
		return "", fmt.Errorf("%w: app name must be 1-32 characters", ErrInvalidInput)
	}
	if name == "RustDesk" {
		return "", fmt.Errorf("%w: app name must differ from RustDesk", ErrInvalidInput)
	}
	if name == "." || name == ".." {
		return "", fmt.Errorf("%w: app name is not a valid path component", ErrInvalidInput)
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return "", fmt.Errorf("%w: app name contains an unsupported character", ErrInvalidInput)
	}
	return name, nil
}

func ValidatePlatforms(in, allowed []string) ([]string, error) {
	if len(allowed) == 0 {
		allowed = SupportedPlatforms
	}
	known := make(map[string]bool, len(allowed))
	for _, platform := range allowed {
		known[platform] = true
	}
	wanted := make(map[string]bool, len(in))
	for _, platform := range in {
		platform = strings.TrimSpace(platform)
		if platform == "" {
			return nil, fmt.Errorf("%w: platform is empty", ErrInvalidInput)
		}
		if !known[platform] {
			return nil, fmt.Errorf("%w: unknown platform %q", ErrInvalidInput, platform)
		}
		wanted[platform] = true
	}
	out := make([]string, 0, len(wanted))
	for _, platform := range allowed {
		if wanted[platform] {
			out = append(out, platform)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: at least one platform is required", ErrInvalidInput)
	}
	return out, nil
}

func ValidateServerKey(key string) error {
	if !serverKeyPattern.MatchString(strings.TrimSpace(key)) {
		return fmt.Errorf("%w: server key is not valid base64", ErrInvalidInput)
	}
	return nil
}

func DeriveServer(relayHost string, hbbsPort uint16) (string, error) {
	host := strings.TrimSpace(relayHost)
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", fmt.Errorf("%w: relay host is required", ErrInvalidInput)
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return "", fmt.Errorf("%w: relay host contains whitespace", ErrInvalidInput)
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", fmt.Errorf("%w: relay host must not contain a port", ErrInvalidInput)
	}
	if hbbsPort == 0 || hbbsPort == 65535 {
		return "", fmt.Errorf("%w: invalid hbbs port", ErrInvalidInput)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(hbbsPort)+1)), nil
}

func ValidateLogoPNG(raw []byte) (Logo, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return Logo{}, fmt.Errorf("%w: logo must be at most 1 MiB", ErrInvalidInput)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return Logo{}, fmt.Errorf("%w: logo is not a PNG: %v", ErrInvalidInput, err)
	}
	if cfg.Width != cfg.Height || cfg.Width < 256 || cfg.Width > 1024 {
		return Logo{}, fmt.Errorf("%w: logo dimensions must be square 256-1024, got %dx%d",
			ErrInvalidInput, cfg.Width, cfg.Height)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return Logo{}, fmt.Errorf("%w: logo is not a decodable PNG: %v", ErrInvalidInput, err)
	}
	var out bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&out, img); err != nil {
		return Logo{}, fmt.Errorf("%w: could not re-encode logo: %v", ErrInvalidInput, err)
	}
	sum := sha256.Sum256(out.Bytes())
	return Logo{
		PNG:    out.Bytes(),
		SHA256: hex.EncodeToString(sum[:]),
		Width:  cfg.Width,
		Height: cfg.Height,
	}, nil
}
