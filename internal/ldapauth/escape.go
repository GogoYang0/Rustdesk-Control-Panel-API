package ldapauth

import (
	"fmt"
	"regexp"
	"strings"
)

// attributeNamePattern is what the configuration may put into a search filter
// as an attribute name. Request input never reaches this position (design L2).
var attributeNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// ValidAttributeName reports whether name may be used as an LDAP attribute
// name in a filter. Attribute names are configuration, not request input, but
// they end up inside the same filter string a username lands in — an
// unvalidated attribute name is just injection with a longer fuse.
func ValidAttributeName(name string) bool {
	return attributeNamePattern.MatchString(name)
}

// EscapeFilter escapes value per RFC 4515 §3 so it can be embedded in an
// assertion value. Every character that could change the filter structure is
// escaped; everything else passes through.
func EscapeFilter(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '\\':
			b.WriteString(`\5c`)
		case '*':
			b.WriteString(`\2a`)
		case '(':
			b.WriteString(`\28`)
		case ')':
			b.WriteString(`\29`)
		case 0:
			b.WriteString(`\00`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// UserFilter builds the search filter for one username: the configured base
// filter wrapped in an AND with the escaped username assertion. The structure
// is fixed here; callers never splice strings into it (design P-L2).
func UserFilter(base, usernameAttribute, username string) string {
	return fmt.Sprintf("(&%s(%s=%s))", base, usernameAttribute, EscapeFilter(username))
}
