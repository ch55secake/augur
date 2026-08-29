package monitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type ProcessController interface {
	Children(context.Context, int) ([]int, error)
	Command(context.Context, int) (string, error)
	Signal(int, os.Signal) error
}

type SystemProcessController struct {
	Runner CommandRunner
}

func (p SystemProcessController) Children(ctx context.Context, pid int) ([]int, error) {
	if p.Runner == nil {
		return nil, errors.New("process controller has no command runner")
	}

	output, err := p.Runner.Run(ctx, "pgrep", "-P", strconv.Itoa(pid))
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 && len(strings.TrimSpace(string(output))) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("find children of PID %d: %w", pid, err)
	}

	var children []int
	for _, value := range strings.Fields(string(output)) {
		child, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("parse child PID %q: %w", value, err)
		}
		if child < 1 {
			return nil, fmt.Errorf("child PID %d is invalid", child)
		}
		children = append(children, child)
	}
	return children, nil
}

func (p SystemProcessController) Command(ctx context.Context, pid int) (string, error) {
	if p.Runner == nil {
		return "", errors.New("process controller has no command runner")
	}

	output, err := p.Runner.Run(ctx, "ps", "-o", "command=", "-p", strconv.Itoa(pid))
	if err != nil {
		return "", fmt.Errorf("read command for PID %d: %w", pid, err)
	}
	return strings.TrimSpace(string(output)), nil
}

func (p SystemProcessController) Signal(pid int, signal os.Signal) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(signal)
}

type TreeTerminator struct {
	Processes   ProcessController
	Connections ConnectionVerifier
}

type ConnectionVerifier interface {
	Verify(context.Context, Connection) (bool, error)
}

func (t TreeTerminator) Terminate(ctx context.Context, connection Connection) error {
	if t.Processes == nil {
		return errors.New("tree terminator has no process controller")
	}

	command, err := t.Processes.Command(ctx, connection.PID)
	if err != nil {
		return err
	}
	if !isSSHSessionCommand(command) {
		return fmt.Errorf("refusing to terminate PID %d with command %q", connection.PID, command)
	}
	if err := t.verifyConnection(ctx, connection); err != nil {
		return err
	}

	return t.terminateTree(ctx, connection, make(map[int]struct{}), true)
}

func (t TreeTerminator) terminateTree(ctx context.Context, connection Connection, visited map[int]struct{}, validate bool) error {
	pid := connection.PID
	if _, seen := visited[pid]; seen {
		return nil
	}
	visited[pid] = struct{}{}

	children, err := t.Processes.Children(ctx, pid)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := t.terminateTree(ctx, Connection{PID: child}, visited, false); err != nil {
			return err
		}
	}
	if validate {
		command, err := t.Processes.Command(ctx, pid)
		if err != nil {
			return err
		}
		if !isSSHSessionCommand(command) {
			return fmt.Errorf("refusing to terminate PID %d after revalidation with command %q", pid, command)
		}
		if err := t.verifyConnection(ctx, connection); err != nil {
			return err
		}
	}

	if err := t.Processes.Signal(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("send SIGTERM to PID %d: %w", pid, err)
	}
	return nil
}

func (t TreeTerminator) verifyConnection(ctx context.Context, connection Connection) error {
	if t.Connections == nil {
		return nil
	}
	verified, err := t.Connections.Verify(ctx, connection)
	if err != nil {
		return err
	}
	if !verified {
		return fmt.Errorf("refusing to terminate PID %d after connection revalidation failed", connection.PID)
	}
	return nil
}

func isSSHSessionCommand(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}

	name := strings.TrimSuffix(filepath.Base(fields[0]), ":")
	return (name == "sshd" || name == "sshd-session") && strings.Contains(fields[0], ":")
}

func isSSHDaemonCommand(command string) bool {
	return command == "sshd" || command == "sshd-session"
}
