package monitor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/ch55secake/augur/internal/config"
)

func TestScanLogsAndTerminatesUnrecognizedConnection(t *testing.T) {
	settings := config.Default()
	settings.Networks = []config.Network{{Name: "trusted", CIDR: "192.168.1.0/24"}}
	settings.Devices = []config.Device{{Name: "trusted-laptop", User: "501", Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	settings.Enforce = true

	var logs bytes.Buffer
	enforcer := &recordingEnforcer{}
	monitor := New(
		fakeDiscoverer{connections: []Connection{
			{PID: 101, User: "501", Local: mustAddrPort(t, "192.168.1.109:22"), Remote: mustAddrPort(t, "192.168.1.50:50000"), State: "ESTABLISHED", PublicKeyFingerprints: []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
			{PID: 102, User: "501", Local: mustAddrPort(t, "192.168.1.109:22"), Remote: mustAddrPort(t, "10.0.0.50:50001"), State: "ESTABLISHED"},
		}},
		enforcer,
		settings,
		slog.New(slog.NewJSONHandler(&logs, nil)),
	)

	if err := monitor.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(enforcer.pids) != 1 || enforcer.pids[0] != 102 {
		t.Fatalf("terminated PIDs = %v, want [102]", enforcer.pids)
	}
	if !strings.Contains(logs.String(), "active SSH connection") || !strings.Contains(logs.String(), "key_fingerprints") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestScanDoesNotEnforceDryRun(t *testing.T) {
	settings := config.Default()
	settings.Networks = []config.Network{{CIDR: "192.168.1.0/24"}}
	settings.Devices = []config.Device{{Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	settings.Enforce = false
	enforcer := &recordingEnforcer{}
	monitor := New(
		fakeDiscoverer{connections: []Connection{{PID: 101, Local: mustAddrPort(t, "192.168.1.109:22"), Remote: mustAddrPort(t, "10.0.0.50:50001"), State: "ESTABLISHED"}}},
		enforcer,
		settings,
		slog.Default(),
	)

	if err := monitor.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(enforcer.pids) != 0 {
		t.Fatalf("terminated PIDs = %v, want none", enforcer.pids)
	}
}

func TestScanResolvesSSHIdentityBeforeMatching(t *testing.T) {
	settings := config.Default()
	settings.Networks = []config.Network{{CIDR: "192.168.1.0/24"}}
	settings.Devices = []config.Device{{Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	settings.Enforce = true
	enforcer := &recordingEnforcer{}
	service := New(
		fakeDiscoverer{connections: []Connection{{
			PID:    101,
			Local:  mustAddrPort(t, "192.168.1.109:22"),
			Remote: mustAddrPort(t, "192.168.1.50:50001"),
			State:  "ESTABLISHED",
		}}},
		enforcer,
		settings,
		slog.Default(),
	)
	service.IdentityResolver = fakeIdentityResolver{identity: SSHIdentity{
		AuthenticationMethods: []string{"publickey"},
		PublicKeyFingerprints: []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}}

	if err := service.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(enforcer.pids) != 0 {
		t.Fatalf("terminated PIDs = %v, want none", enforcer.pids)
	}
}

func TestScanCachesNetworkInventoryWithoutChangingSSHEnforcement(t *testing.T) {
	settings := config.Default()
	settings.Networks = []config.Network{{Name: "lan", CIDR: "192.168.1.0/24"}}
	settings.ProbeNetworks = []string{"lan"}
	settings.NetworkProbes.Enabled = true
	settings.Enforce = false
	prober := &fakeNetworkProber{observations: []NetworkObservation{{Address: mustAddr(t, "192.168.1.50")}}}
	service := New(
		fakeDiscoverer{},
		&recordingEnforcer{},
		settings,
		slog.Default(),
	)
	service.NetworkProber = prober

	if err := service.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := service.NetworkInventory(); len(got) != 1 || got[0].Address != mustAddr(t, "192.168.1.50") {
		t.Fatalf("network inventory = %#v", got)
	}
	if err := service.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if prober.calls != 1 {
		t.Fatalf("probe calls = %d, want one within the probe interval", prober.calls)
	}
}

func TestScanContinuesSSHEnforcementWhenNetworkProbeFails(t *testing.T) {
	settings := config.Default()
	settings.Networks = []config.Network{{Name: "lan", CIDR: "192.168.1.0/24"}}
	settings.ProbeNetworks = []string{"lan"}
	settings.NetworkProbes.Enabled = true
	settings.Enforce = true
	enforcer := &recordingEnforcer{}
	service := New(
		fakeDiscoverer{connections: []Connection{{
			PID:    101,
			Local:  mustAddrPort(t, "192.168.1.109:22"),
			Remote: mustAddrPort(t, "192.168.1.50:50001"),
			State:  "ESTABLISHED",
		}}},
		enforcer,
		settings,
		slog.Default(),
	)
	service.NetworkProber = &fakeNetworkProber{err: errors.New("probe unavailable")}

	if err := service.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(enforcer.pids) != 1 || enforcer.pids[0] != 101 {
		t.Fatalf("terminated PIDs = %v, want [101]", enforcer.pids)
	}
}

type fakeDiscoverer struct {
	connections []Connection
	err         error
}

func (d fakeDiscoverer) Discover(context.Context) ([]Connection, error) {
	return d.connections, d.err
}

type recordingEnforcer struct {
	pids []int
}

func (e *recordingEnforcer) Terminate(_ context.Context, connection Connection) error {
	e.pids = append(e.pids, connection.PID)
	return nil
}

type fakeIdentityResolver struct {
	identity SSHIdentity
	err      error
}

func (r fakeIdentityResolver) Resolve(context.Context, Connection) (SSHIdentity, error) {
	return r.identity, r.err
}

type fakeNetworkProber struct {
	observations []NetworkObservation
	err          error
	calls        int
}

func (p *fakeNetworkProber) Probe(_ context.Context, _ []netip.Prefix, _ config.NetworkProbeConfig) ([]NetworkObservation, error) {
	p.calls++
	return p.observations, p.err
}
