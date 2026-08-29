package monitor

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func TestTreeTerminatorSignalsChildrenBeforeRoot(t *testing.T) {
	processes := &fakeProcesses{
		commands: map[int]string{101: "sshd: alice@ttys001"},
		children: map[int][]int{101: {102, 103}, 102: {104}},
	}
	terminator := TreeTerminator{Processes: processes}

	if err := terminator.Terminate(context.Background(), Connection{PID: 101}); err != nil {
		t.Fatal(err)
	}

	want := []int{104, 102, 103, 101}
	if !reflect.DeepEqual(processes.signals, want) {
		t.Fatalf("signals = %v, want %v", processes.signals, want)
	}
}

func TestTreeTerminatorRefusesListener(t *testing.T) {
	processes := &fakeProcesses{commands: map[int]string{101: "sshd -D"}}
	terminator := TreeTerminator{Processes: processes}

	if err := terminator.Terminate(context.Background(), Connection{PID: 101}); err == nil {
		t.Fatal("listener was accepted for termination")
	}
	if len(processes.signals) != 0 {
		t.Fatalf("signals = %v, want none", processes.signals)
	}
}

func TestTreeTerminatorAcceptsSplitSSHSessionProcess(t *testing.T) {
	processes := &fakeProcesses{commands: map[int]string{101: "sshd-session: alice@ttys001"}}
	terminator := TreeTerminator{Processes: processes}

	if err := terminator.Terminate(context.Background(), Connection{PID: 101}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(processes.signals, []int{101}) {
		t.Fatalf("signals = %v, want [101]", processes.signals)
	}
}

func TestTreeTerminatorRevalidatesConnectionBeforeSignal(t *testing.T) {
	processes := &fakeProcesses{commands: map[int]string{101: "sshd: alice@ttys001"}}
	verifier := &recordingConnectionVerifier{verified: true}
	terminator := TreeTerminator{Processes: processes, Connections: verifier}

	if err := terminator.Terminate(context.Background(), Connection{PID: 101}); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 2 {
		t.Fatalf("connection verifications = %d, want 2", verifier.calls)
	}
}

type fakeProcesses struct {
	commands map[int]string
	children map[int][]int
	signals  []int
}

type recordingConnectionVerifier struct {
	verified bool
	calls    int
}

func (v *recordingConnectionVerifier) Verify(context.Context, Connection) (bool, error) {
	v.calls++
	return v.verified, nil
}

func (p *fakeProcesses) Children(_ context.Context, pid int) ([]int, error) {
	return p.children[pid], nil
}

func (p *fakeProcesses) Command(_ context.Context, pid int) (string, error) {
	return p.commands[pid], nil
}

func (p *fakeProcesses) Signal(pid int, _ os.Signal) error {
	p.signals = append(p.signals, pid)
	return nil
}
