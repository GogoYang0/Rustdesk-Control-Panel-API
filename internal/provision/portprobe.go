package provision

import (
	"fmt"
	"net"
)

// PortChecker reports whether a host port can be bound for the given network
// ("tcp" or "udp"). A nil error means the port is free.
type PortChecker func(port uint16, network string) error

// hostPortChecker binds the wildcard address Docker publishes on and releases
// it immediately. The check is advisory: another process can take the port
// between the probe and the deploy, which Docker then reports itself.
func hostPortChecker(port uint16, network string) error {
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return err
		}
		return ln.Close()
	case "udp":
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
		if err != nil {
			return err
		}
		return conn.Close()
	default:
		return fmt.Errorf("unsupported network %q", network)
	}
}
