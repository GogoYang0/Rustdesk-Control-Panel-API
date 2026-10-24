package provision

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostPortChecker_DetectsInUse(t *testing.T) {
	// Bind the same wildcard IPv4 address the checker uses: a loopback-only
	// listener coexists with the wildcard on Windows and would not prove the
	// check works.
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	require.NoError(t, err)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	require.Error(t, hostPortChecker(port, "tcp"), "a bound port must be reported as occupied")

	require.NoError(t, ln.Close())
	require.NoError(t, hostPortChecker(port, "tcp"), "the port must be free after the listener closes")
}
