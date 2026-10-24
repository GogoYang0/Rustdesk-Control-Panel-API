package provision

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrPortConflict is returned when a host port a deployment needs is already
// bound by a process outside the panel.
var ErrPortConflict = errors.New("host port already in use")

// PortChecker reports whether a host port can be bound for the given network
// ("tcp" or "udp"). A nil error means the port is free.
type PortChecker func(port uint16, network string) error

// PortConflict describes one occupied port found by a probe.
type PortConflict struct {
	Port    uint16
	Network string
	Err     error
}

// String renders the conflict for logs and error messages.
func (c PortConflict) String() string {
	if c.Err == nil {
		return fmt.Sprintf("%d/%s", c.Port, c.Network)
	}
	return fmt.Sprintf("%d/%s: %v", c.Port, c.Network, c.Err)
}

// portSpec is one host port and the protocol the block publishes it on.
type portSpec struct {
	port    uint16
	network string
}

// blockPortSpecs lists every host port a deployment block binds: hbbs uses
// three upstream ports, hbbr two, and only the main id-registry port is also
// bound over UDP.
func blockPortSpecs(base uint16) []portSpec {
	return []portSpec{
		{base, "tcp"},     // hbbs 21115, NAT type test
		{base + 1, "tcp"}, // hbbs 21116, id registry
		{base + 1, "udp"}, // hbbs 21116, id registry
		{base + 2, "tcp"}, // hbbs 21118, websocket
		{base + 3, "tcp"}, // hbbr 21117, relay
		{base + 4, "tcp"}, // hbbr 21119, relay websocket
	}
}

// checkBlock returns the first occupied port of a deployment block.
func (s *Service) checkBlock(base uint16) *PortConflict {
	for _, spec := range blockPortSpecs(base) {
		if err := s.checker(spec.port, spec.network); err != nil {
			return &PortConflict{Port: spec.port, Network: spec.network, Err: err}
		}
	}
	return nil
}

// portSpan is an inclusive port range reserved by a ServerGroup row.
type portSpan struct {
	start uint32
	end   uint32
}

// ProbePortRange reports host ports in [portStart, portEnd] that are occupied
// by processes outside the panel. Reserved blocks are skipped: their ports are
// expected to be bound by the panel's own containers. The probe is advisory and
// never reserves anything.
func (s *Service) ProbePortRange(ctx context.Context) ([]PortConflict, error) {
	start, end := s.cfg.PortStart, s.cfg.PortEnd
	// Compare in uint32: start+PortBlockSize-1 overflows uint16 at the top of
	// the range and would let an impossible range pass validation.
	if start == 0 || uint32(end) < uint32(start)+PortBlockSize-1 {
		return nil, fmt.Errorf("invalid port range %d-%d", start, end)
	}

	var rows []model.ServerGroup
	// Host ports are a machine-level resource, so this lookup spans tenants.
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).
		Select("hbbs_port", "hbbr_port").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list reserved port blocks: %w", err)
	}

	spans := make([]portSpan, 0, len(rows))
	for _, r := range rows {
		rStart := uint32(r.HbbsPort)
		// hbbr publishes HbbrPort and HbbrPort+1; fall back to the full block
		// width for rows written by an older layout.
		rEnd := uint32(r.HbbrPort) + 1
		if rEnd < rStart+PortBlockSize-1 {
			rEnd = rStart + PortBlockSize - 1
		}
		spans = append(spans, portSpan{start: rStart, end: rEnd})
	}

	conflicts := make([]PortConflict, 0)
	for base := uint32(start); base+PortBlockSize-1 <= uint32(end); base += PortBlockSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if overlapsAny(spans, base, base+PortBlockSize-1) {
			continue
		}
		for _, spec := range blockPortSpecs(uint16(base)) {
			if err := s.checker(spec.port, spec.network); err != nil {
				conflicts = append(conflicts, PortConflict{Port: spec.port, Network: spec.network, Err: err})
			}
		}
	}
	return conflicts, nil
}

// overlapsAny reports whether [start,end] intersects any reserved span.
func overlapsAny(spans []portSpan, start, end uint32) bool {
	for _, span := range spans {
		if span.start <= end && start <= span.end {
			return true
		}
	}
	return false
}

// hostPortChecker binds the wildcard IPv4 address Docker publishes on and
// releases it immediately. Windows keeps a loopback-only listener and the IPv4
// wildcard independent, so an explicit 0.0.0.0 bind is the closest simulation
// of what the container proxy needs. The check is advisory: another process can
// take the port between the probe and the deploy, which Docker then reports
// itself.
func hostPortChecker(port uint16, network string) error {
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			return err
		}
		return ln.Close()
	case "udp":
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)})
		if err != nil {
			return err
		}
		return conn.Close()
	default:
		return fmt.Errorf("unsupported network %q", network)
	}
}
