package monitor

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/ch55secake/augur/internal/config"
)

func TestScanLogsAndTerminatesUnrecognizedConnection(t *testing.T) {
	settings := config.Default()
	settings.Networks = []config.Network{{Name: "trusted", CIDR: "192.168.1.0/24"}}
	settings.Enforce = true

	var logs bytes.Buffer
	enforcer := &recordingEnforcer{}
	monitor := New(
		fakeDiscoverer{connections: []Connection{
			{PID: 101, User: "501", Local: mustAddrPort(t, "192.168.1.109:22"), Remote: mustAddrPort(t, "192.168.1.50:50000"), State: "ESTABLISHED"},
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
	if !strings.Contains(logs.String(), "active SSH connection") || !strings.Contains(logs.String(), "network_fingerprint") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestScanDoesNotEnforceDryRun(t *testing.T) {
	settings := config.Default()
	settings.Networks = []config.Network{{CIDR: "192.168.1.0/24"}}
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

func (e *recordingEnforcer) Terminate(_ context.Context, pid int) error {
	e.pids = append(e.pids, pid)
	return nil
}
