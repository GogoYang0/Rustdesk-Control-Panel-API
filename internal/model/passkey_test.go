package model

import (
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

func tableNameOf(t *testing.T, m any) string {
	t.Helper()
	s, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse schema for %T: %v", m, err)
	}
	return s.Table
}

// TestPersistentModels_IncludesPasskeyTables pins the two new tables into the
// AutoMigrate registry: a table that only exists in code is missing in
// production exactly the way Strategy/DeviceDisconnect were in wave 4.
func TestPersistentModels_IncludesPasskeyTables(t *testing.T) {
	got := map[string]bool{}
	for _, m := range PersistentModels() {
		got[tableNameOf(t, m)] = true
	}
	for _, want := range []string{"user_passkeys", "webauthn_ceremonies"} {
		if !got[want] {
			t.Fatalf("%s missing from PersistentModels()", want)
		}
	}
}

// TestCeremonyPurpose_Distinct keeps the three ceremony kinds in separate
// constant families; sharing strings is how wave 3 mixed approve/approved.
func TestCeremonyPurpose_Distinct(t *testing.T) {
	purposes := []CeremonyPurpose{CeremonyRegister, CeremonyLogin, CeremonyStepup}
	seen := map[CeremonyPurpose]bool{}
	for _, p := range purposes {
		if seen[p] {
			t.Fatalf("duplicate ceremony purpose %q", p)
		}
		seen[p] = true
	}
}
