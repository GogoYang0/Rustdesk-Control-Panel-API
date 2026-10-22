// Package logcollect tails the hbbs/hbbr containers of every provisioned
// organization, parses their log lines with configurable rules and stores the
// results as tenant-scoped LogEvent rows. It also feeds the device liveness
// auxiliary source (C11): a parsed connection line refreshes the device
// heartbeat.
package logcollect

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// Rule is one configured parsing rule (mirrors config.LogcollectRule).
type Rule struct {
	Name    string
	Pattern string
	Level   string
	Kind    string
}

// ParsedEvent is one successfully matched log line.
type ParsedEvent struct {
	Rule   string
	Level  string
	Kind   string
	Detail map[string]any
	// DeviceRustdeskID comes from the named capture group "device"; empty
	// when the line carries no device reference.
	DeviceRustdeskID string
	OccurredAt       time.Time
}

// Parser applies the configured rules to raw log lines. Rules are evaluated
// in order and the first match wins; a line that matches nothing increments
// parseErrors and is dropped instead of failing the tailer (C7).
type Parser struct {
	rules       []compiledRule
	parseErrors atomic.Uint64
}

type compiledRule struct {
	name   string
	re     *regexp.Regexp
	level  string
	kind   string
	groups []string // subexpression names, index-aligned with FindStringSubmatch
}

// NewParser compiles the rules, rejecting invalid regular expressions so a
// misconfiguration fails at startup instead of silently dropping every line.
func NewParser(rules []Rule) (*Parser, error) {
	p := &Parser{}
	for i, r := range rules {
		if strings.TrimSpace(r.Pattern) == "" {
			return nil, fmt.Errorf("logcollect rule %d (%s): empty pattern", i, r.Name)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("logcollect rule %d (%s): %w", i, r.Name, err)
		}
		p.rules = append(p.rules, compiledRule{
			name:   r.Name,
			re:     re,
			level:  normalizeLevel(r.Level),
			kind:   normalizeKind(r.Kind),
			groups: re.SubexpNames(),
		})
	}
	return p, nil
}

// Rules reports the number of configured rules.
func (p *Parser) Rules() int { return len(p.rules) }

// ParseErrors reports how many lines were dropped as unparseable.
func (p *Parser) ParseErrors() uint64 { return p.parseErrors.Load() }

// Parse tries every rule in order; ok is false when no rule matched.
func (p *Parser) Parse(line string, at time.Time) (ParsedEvent, bool) {
	for _, r := range p.rules {
		m := r.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		detail := map[string]any{"raw": truncateValue(line)}
		device := ""
		for i, name := range r.groups {
			if i == 0 || name == "" || i >= len(m) {
				continue
			}
			if name == "device" {
				device = m[i]
				continue
			}
			detail[name] = truncateValue(m[i])
		}
		return ParsedEvent{
			Rule:             r.name,
			Level:            r.level,
			Kind:             r.kind,
			Detail:           detail,
			DeviceRustdeskID: device,
			OccurredAt:       at,
		}, true
	}
	p.parseErrors.Add(1)
	return ParsedEvent{}, false
}

// maxDetailValueBytes bounds every string stored in the event detail. The
// scanner accepts up to maxLineBytes, and a rule such as (?P<msg>.*) captures
// the whole line, so unbounded values would store megabytes per event.
const maxDetailValueBytes = 4096

// truncateValue bounds one detail string: storing megabyte lines is a privacy
// and storage risk even when a single line is legitimate. The cut backs off to
// a character boundary, because slicing inside a multi-byte rune would store
// invalid UTF-8 that JSON encoding turns into a replacement character.
func truncateValue(s string) string {
	if len(s) <= maxDetailValueBytes {
		return s
	}
	cut := maxDetailValueBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(truncated)"
}

// normalizeLevel clamps unknown levels to info.
func normalizeLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case model.LogLevelWarn, model.LogLevelError:
		return strings.ToLower(strings.TrimSpace(level))
	default:
		return model.LogLevelInfo
	}
}

// normalizeKind clamps unknown kinds to other.
func normalizeKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case model.LogKindConn, model.LogKindFile, model.LogKindError, model.LogKindDisconnected:
		return strings.ToLower(strings.TrimSpace(kind))
	default:
		return model.LogKindOther
	}
}
