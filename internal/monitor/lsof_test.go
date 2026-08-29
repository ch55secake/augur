package monitor

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"reflect"
	"testing"
)

func TestParseLsofOutput(t *testing.T) {
	data := []byte("p101\ncsshd\nu501\nn192.168.1.109:22->192.168.1.50:54321\nTST=ESTABLISHED\np102\ncsshd\nu501\nn192.168.1.109:2222->[fd00::50]:54322\nTST=ESTABLISHED\np103\ncsshd\nu501\nn192.168.1.109:22->192.168.1.60:54323\nTST=CLOSED\n")

	connections, err := ParseLsofOutput(data, map[int]struct{}{22: {}})
	if err != nil {
		t.Fatal(err)
	}

	want := []Connection{{
		PID:     101,
		Command: "sshd",
		User:    "501",
		Local:   mustAddrPort(t, "192.168.1.109:22"),
		Remote:  mustAddrPort(t, "192.168.1.50:54321"),
		State:   "ESTABLISHED",
	}}
	if !reflect.DeepEqual(connections, want) {
		t.Fatalf("connections = %#v, want %#v", connections, want)
	}
}

func TestLsofDiscoverer(t *testing.T) {
	runner := &fakeRunner{output: []byte("p101\ncsshd\nu501\nn192.168.1.109:22->192.168.1.50:54321\nTST=ESTABLISHED\n")}
	discoverer := NewLsofDiscoverer(runner, []int{22})

	connections, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 1 || connections[0].PID != 101 {
		t.Fatalf("connections = %#v", connections)
	}
	if runner.name != "lsof" {
		t.Fatalf("command = %q, want lsof", runner.name)
	}
}

func TestLsofDiscovererTreatsNoMatchesAsEmpty(t *testing.T) {
	discoverer := NewLsofDiscoverer(&fakeRunner{err: exitError(1)}, []int{22})

	connections, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 0 {
		t.Fatalf("connections = %#v, want none", connections)
	}
}

type fakeRunner struct {
	output []byte
	err    error
	name   string
	args   []string
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.name = name
	r.args = args
	return r.output, r.err
}

func exitError(status int) error {
	command := exec.Command("sh", "-c", fmt.Sprintf("exit %d", status))
	_, err := command.Output()
	return err
}

func mustAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}
