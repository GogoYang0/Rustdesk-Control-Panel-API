package model

// PersistentModels returns every model AutoMigrate must create or update.
// Scoped models are covered by a test in internal/store; RecoveryCode is a
// JSON payload type, not a table.
func PersistentModels() []any {
	return []any{
		&User{}, &RefreshToken{}, &UserTOTP{},
		&Organization{}, &Membership{}, &Role{}, &Invitation{}, &APIToken{}, &AuditLog{},
		&Device{}, &DeviceHeartbeat{}, &ServerGroup{},
		&AddressBook{}, &AddressBookPeer{}, &AddressBookTag{}, &AddressBookGrant{}, &SyncCursor{},
		&VerificationToken{}, &MigrationMark{}, &CompatSession{}, &LogEvent{},
		&Session{}, &SessionEvent{}, &Ticket{}, &Policy{}, &Approval{}, &Alert{},
		&UserGroup{}, &UserGroupMember{}, &DeviceGroup{}, &AccessRule{},
		&ControlRole{}, &ConnectionLog{}, &FileLog{}, &AuditNonce{},
		&CompatLoginChallenge{}, &Strategy{}, &DeviceDisconnect{},
	}
}
