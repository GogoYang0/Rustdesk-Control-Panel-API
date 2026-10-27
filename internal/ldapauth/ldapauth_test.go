package ldapauth

import (
	"context"
	"errors"
	"testing"
)

func TestEscapeFilter(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"alice", "alice"},
		{"*", "\\2a"},
		{"(", "\\28"},
		{")", "\\29"},
		{"\\", "\\5c"},
		{"\x00", "\\00"},
		{")(uid=*", "\\29\\28uid=\\2a"},
		{"a*b(c)d\\e", "a\\2ab\\28c\\29d\\5ce"},
		// RFC 4515 only mandates the five characters above; everything else
		// (spaces, #, +, <, >, =, non-ASCII) passes through untouched.
		{"#  +<>=ü", "#  +<>=ü"},
	}
	for _, tc := range cases {
		if got := EscapeFilter(tc.in); got != tc.want {
			t.Errorf("EscapeFilter(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUserFilter(t *testing.T) {
	got := UserFilter("(objectClass=person)", "uid", "ali*ce")
	want := "(&(objectClass=person)(uid=ali\\2ace))"
	if got != want {
		t.Fatalf("UserFilter = %q, want %q", got, want)
	}
}

func TestValidAttributeName(t *testing.T) {
	for _, name := range []string{"uid", "sAMAccountName", "mail", "a"} {
		if !ValidAttributeName(name) {
			t.Errorf("ValidAttributeName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"", "1uid", "uid,name", "uid name", "uid=", "-uid"} {
		if ValidAttributeName(name) {
			t.Errorf("ValidAttributeName(%q) = true, want false", name)
		}
	}
}

func TestFake_Authenticate(t *testing.T) {
	fake := NewFake(map[string]FakeUser{
		"alice": {Mail: "ldap-alice@example.com", Password: "secret"},
	})

	email, err := fake.Authenticate(context.Background(), "alice", "secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if email != "ldap-alice@example.com" {
		t.Fatalf("email = %q", email)
	}
	if fake.DialCount() != 1 {
		t.Fatalf("dial count = %d, want 1", fake.DialCount())
	}

	if _, err := fake.Authenticate(context.Background(), "alice", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := fake.Authenticate(context.Background(), "nobody", "secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user = %v, want ErrInvalidCredentials (no user enumeration)", err)
	}
}

// TestFake_DialCountForEmptyCredentials pins the L1 evidence channel: the fake
// must refuse empty credentials BEFORE counting a dial, so the HTTP test can
// prove the production code never touches the directory for them.
func TestFake_DialCountForEmptyCredentials(t *testing.T) {
	fake := NewFake(nil)

	if _, err := fake.Authenticate(context.Background(), "alice", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := fake.Authenticate(context.Background(), "", "secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty username = %v, want ErrInvalidCredentials", err)
	}
	if fake.DialCount() != 0 {
		t.Fatalf("dial count = %d, want 0 (empty credentials must not reach the directory)", fake.DialCount())
	}
}

func TestFake_ErrorKnobs(t *testing.T) {
	fake := NewFake(nil)
	fake.Unavailable = true
	if _, err := fake.Authenticate(context.Background(), "alice", "secret"); !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("unavailable = %v, want ErrDirectoryUnavailable", err)
	}

	fake = NewFake(map[string]FakeUser{"alice": {Mail: "", Password: "s"}})
	if _, err := fake.Authenticate(context.Background(), "alice", "s"); !errors.Is(err, ErrMissingMail) {
		t.Fatalf("missing mail = %v, want ErrMissingMail", err)
	}

	fake = NewFake(nil)
	fake.Ambiguous = true
	if _, err := fake.Authenticate(context.Background(), "alice", "s"); !errors.Is(err, ErrAmbiguousResult) {
		t.Fatalf("ambiguous = %v, want ErrAmbiguousResult", err)
	}
}
