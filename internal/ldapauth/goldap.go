package ldapauth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// Config carries the runtime settings the production Directory needs. It is a
// projection of config.LDAPConfig without the validation-only fields, so this
// package does not import the config tree.
type Config struct {
	Host               string
	Port               int
	Transport          string // ldaps | starttls | none
	AllowInsecure      bool
	InsecureSkipVerify bool
	BaseDN             string
	Scope              string // one | sub
	BindDN             string
	BindPassword       string
	UserFilter         string
	UsernameAttribute  string
	MailAttribute      string
	Timeout            time.Duration
}

// GoLDAP is the production Directory: one connection per authentication
// (service bind → search → user bind), no pooling (design §2).
type GoLDAP struct {
	cfg Config
}

// NewGoLDAP builds the production directory client.
func NewGoLDAP(cfg Config) *GoLDAP {
	return &GoLDAP{cfg: cfg}
}

// Authenticate runs the three-step bind: dial, service-account bind, search
// for exactly one entry, then bind as that entry with the user's password.
// The user's password never survives this call: it goes into the bind request
// and nothing else (design P-L4).
func (g *GoLDAP) Authenticate(ctx context.Context, username, password string) (string, error) {
	// L1, mirrored in the production client itself: an empty password plus a
	// simple bind is an anonymous bind on many directories, and the server
	// answers success. The handler refuses earlier; this is the second gate.
	if strings.TrimSpace(username) == "" || password == "" {
		return "", ErrInvalidCredentials
	}

	conn, err := g.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close() //nolint:errcheck // a closed socket has no error path that changes the outcome

	if err := conn.Bind(g.cfg.BindDN, g.cfg.BindPassword); err != nil {
		return "", fmt.Errorf("%w: service bind failed: %v", ErrDirectoryUnavailable, err)
	}

	search := goldap.NewSearchRequest(
		g.cfg.BaseDN,
		g.scope(),
		goldap.NeverDerefAliases,
		2, // SizeLimit: one hit is a login, two is an ambiguous filter (L6)
		0,
		false,
		UserFilter(g.cfg.UserFilter, g.cfg.UsernameAttribute, username),
		[]string{g.cfg.UsernameAttribute, g.cfg.MailAttribute},
		nil,
	)
	result, err := conn.Search(search)
	if err != nil {
		// A size-limit hit means the filter matched at least the two entries we
		// asked for: ambiguous, not broken (L6).
		if goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) {
			return "", ErrAmbiguousResult
		}
		return "", fmt.Errorf("%w: user search failed: %v", ErrDirectoryUnavailable, err)
	}
	if len(result.Entries) == 0 {
		// One message for "no such user" and "wrong password": the directory
		// must not become a user-enumeration oracle (P-L5).
		return "", ErrInvalidCredentials
	}
	if len(result.Entries) > 1 {
		return "", ErrAmbiguousResult
	}

	entry := result.Entries[0]

	// The user bind is the password check, and it runs BEFORE the mail read:
	// answering 403 for an entry the caller has not authenticated against would
	// confirm that the username exists without knowing the password (P-L5).
	if err := conn.Bind(entry.DN, password); err != nil {
		// Only a code-49 bind rejection is credentials. A reset socket, a TLS
		// failure or a timeout here are infrastructure: misreporting them as
		// 401 would feed a directory outage into the account lockout windows
		// and show up as password guessing on the monitoring side.
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("%w: user bind failed: %v", ErrDirectoryUnavailable, err)
	}

	mail := strings.TrimSpace(entry.GetAttributeValue(g.cfg.MailAttribute))
	if mail == "" {
		return "", ErrMissingMail
	}
	return mail, nil
}

// dial opens one connection with the configured transport. Every failure maps
// to ErrDirectoryUnavailable: an unreachable or misconfigured directory must
// never look like "wrong password" (design L5, P-L5).
func (g *GoLDAP) dial(ctx context.Context) (*goldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", g.cfg.Host, g.cfg.Port)
	timeout := g.cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var opts []goldap.DialOpt
	opts = append(opts, goldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	var tlsCfg *tls.Config
	if g.cfg.InsecureSkipVerify {
		tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit, warned-at-startup operator decision (L3)
	}

	var conn *goldap.Conn
	var err error
	switch g.cfg.Transport {
	case "ldaps":
		opts = append(opts, goldap.DialWithTLSConfig(tlsCfg))
		conn, err = goldap.DialURL("ldaps://"+addr, opts...)
	case "starttls":
		conn, err = goldap.DialURL("ldap://"+addr, opts...)
		if err == nil {
			if tlsCfg == nil {
				tlsCfg = &tls.Config{ServerName: g.cfg.Host}
			}
			if err = conn.StartTLS(tlsCfg); err != nil {
				err = fmt.Errorf("starttls: %w", err)
			}
		}
	case "none":
		if !g.cfg.AllowInsecure {
			// The configuration validates this at startup; the second gate here
			// keeps a mis-edited config from leaking passwords at runtime.
			return nil, fmt.Errorf("%w: plaintext transport requires ldap.allowInsecure", ErrDirectoryUnavailable)
		}
		conn, err = goldap.DialURL("ldap://"+addr, opts...)
	default:
		return nil, fmt.Errorf("%w: unknown transport %q", ErrDirectoryUnavailable, g.cfg.Transport)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: connect %s: %v", ErrDirectoryUnavailable, addr, err)
	}
	conn.SetTimeout(timeout)
	return conn, nil
}

func (g *GoLDAP) scope() int {
	if g.cfg.Scope == "one" {
		return goldap.ScopeSingleLevel
	}
	return goldap.ScopeWholeSubtree
}
