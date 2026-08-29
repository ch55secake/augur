package monitor

import (
	"fmt"
	"net/netip"
)

type Connection struct {
	PID                   int
	Command               string
	User                  string
	Local                 netip.AddrPort
	Remote                netip.AddrPort
	State                 string
	AuthenticationMethods []string
	PublicKeyFingerprints []string
}

func (c Connection) NetworkFingerprint() string {
	return c.Remote.Addr().Unmap().String()
}

func (c Connection) Key() string {
	return fmt.Sprintf("%d/%s", c.PID, c.Remote.String())
}
