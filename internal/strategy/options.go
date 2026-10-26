package strategy

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits mirrored by the contract. They are defence in depth: the whitelist is
// already smaller than the key cap, so the cap only guards future growth.
const (
	MaxOptionsPerStrategy = 50
	MaxOptionValueLen     = 256
	// MaxNameLen matches the contract's 64-rune limit on strategy names.
	MaxNameLen = 64
)

// allowedOptions is the single source of truth for deliverable client options.
//
// The client applies every key it receives without a whitelist of its own
// (src/hbbs_http/sync.rs, handle_config_options), so this list is the only
// thing standing between an administrator and device takeover: api-server,
// custom-rendezvous-server, relay-server and key would all redirect or re-key
// the endpoint. Adding a key therefore requires changing this list, the API
// spec and the tests together.
var allowedOptions = []string{
	"enable-audio",
	"enable-clipboard",
	"enable-file-transfer",
	"enable-file-copy-paste",
	"enable-camera",
	"enable-terminal",
	"enable-tunnel",
	"enable-remote-restart",
	"enable-record-session",
	"enable-block-input",
	"enable-privacy-mode",
	"enable-remote-modify",
	"enable-remote-printer",
	"enable-check-update",
	"disable-change-id",
	"disable-settings",
	"disable-installation",
	"disable-unlock-pin",
	"disable-tcp-listen",
	"disable-ab",
}

// AllowedOptions returns the whitelist in a stable order.
func AllowedOptions() []string {
	out := make([]string, len(allowedOptions))
	copy(out, allowedOptions)
	return out
}

// allowlist is the lookup form of allowedOptions.
var allowlist = func() map[string]bool {
	m := make(map[string]bool, len(allowedOptions))
	for _, k := range allowedOptions {
		m[k] = true
	}
	return m
}()

// NormalizeOptions validates an option map and returns a copy.
//
// Keys are matched byte for byte: no trimming, no case folding. The client
// stores whatever spelling arrives, so accepting " enable-audio" would create
// an option nobody reads while looking like the real one — an allowed key must
// be spelled exactly. Values are free-form because the client parses them
// itself ("Y"/"N" for switches, an empty value clears the option), but they are
// bounded and must not contain control characters: the value ends up in the
// client's configuration file.
func NormalizeOptions(in map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(in))
	if len(in) > MaxOptionsPerStrategy {
		return nil, fmt.Errorf("%w: at most %d options", ErrInvalidOptionValue, MaxOptionsPerStrategy)
	}
	for k, v := range in {
		if !allowlist[k] {
			return nil, fmt.Errorf("%w: %s", ErrUnknownOption, k)
		}
		if utf8.RuneCountInString(v) > MaxOptionValueLen {
			return nil, fmt.Errorf("%w: %s exceeds %d characters", ErrInvalidOptionValue, k, MaxOptionValueLen)
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return nil, fmt.Errorf("%w: %s contains a control character", ErrInvalidOptionValue, k)
			}
		}
		out[k] = v
	}
	return out, nil
}

// NormalizeOptionKeys returns the keys of an option map in sorted order; the
// audit detail uses it so two equivalent payloads look identical in the trail.
func NormalizeOptionKeys(in map[string]string) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalizeName trims and bounds a strategy name.
func normalizeName(v string) (string, error) {
	name := strings.TrimSpace(v)
	if name == "" || utf8.RuneCountInString(name) > MaxNameLen {
		return "", ErrInvalidName
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrInvalidName
		}
	}
	return name, nil
}
