// Package controlrole owns the in-session permission model that RustDesk calls
// a "Control Role": fourteen permissions, each in one of three states, on a
// per-organization role that a member may be assigned.
//
// It deliberately does not enforce anything on native sessions. hbbs injects
// ControlPermissions into PunchHole / RequestRelay / FetchLocalAddr, and this
// panel is not in the signalling path (design D10); the ticket snapshot is the
// only place the computed value travels today.
package controlrole

// State is one permission's tri-state. "use_client" means "do not override the
// controlled device's local setting", which is also the value a missing key
// takes.
type State string

// The three states a permission can hold (RustDesk Server Pro semantics).
const (
	StateUseClient State = "use_client"
	StateEnable    State = "enable"
	StateDisable   State = "disable"
)

// DefaultRoleName is the name of the per-organization built-in role. It is
// fixed: the row is seeded by Migrate and cannot be renamed or deleted.
const DefaultRoleName = "Default"

// keys is the wire order of RustDesk's ControlPermissions.Permission enum
// (libs/hbb_common/protos/rendezvous.proto). The slice index IS the bit number,
// so appending is forbidden — a new permission must be added with the value the
// client protocol uses.
var keys = []string{
	"keyboard",       // bit 0
	"remote_printer", // bit 1
	"clipboard",      // bit 2
	"file",           // bit 3
	"audio",          // bit 4
	"camera",         // bit 5
	"terminal",       // bit 6
	"tunnel",         // bit 7
	"restart",        // bit 8
	"recording",      // bit 9
	"block_input",    // bit 10
	"remote_modify",  // bit 11
	"privacy_mode",   // bit 12
	"usb",            // bit 13
}

// Keys returns the permission keys in protocol order.
func Keys() []string {
	out := make([]string, len(keys))
	copy(out, keys)
	return out
}

// Permissions is a role's permission set, keyed by protocol name.
type Permissions map[string]State

// DefaultPermissions returns every permission in the "use_client" state: a role
// that overrides nothing.
func DefaultPermissions() Permissions {
	out := make(Permissions, len(keys))
	for _, k := range keys {
		out[k] = StateUseClient
	}
	return out
}
