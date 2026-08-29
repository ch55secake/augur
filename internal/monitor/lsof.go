package monitor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type LsofDiscoverer struct {
	Runner CommandRunner
	Ports  map[int]struct{}
}

func NewLsofDiscoverer(runner CommandRunner, ports []int) LsofDiscoverer {
	portSet := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		portSet[port] = struct{}{}
	}
	return LsofDiscoverer{Runner: runner, Ports: portSet}
}

func (d LsofDiscoverer) Discover(ctx context.Context) ([]Connection, error) {
	if d.Runner == nil {
		return nil, fmt.Errorf("lsof discoverer has no command runner")
	}

	output, err := d.Runner.Run(ctx, "lsof", "-nP", "-a", "-c", "sshd", "-iTCP", "-sTCP:ESTABLISHED", "-FpcunT")
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 && len(strings.TrimSpace(string(output))) == 0 {
			return []Connection{}, nil
		}
		return nil, fmt.Errorf("run lsof: %w", err)
	}

	return ParseLsofOutput(output, d.Ports)
}

type lsofRecord struct {
	pid         int
	command     string
	user        string
	names       []string
	established bool
	hasState    bool
}

func ParseLsofOutput(data []byte, ports map[int]struct{}) ([]Connection, error) {
	var connections []Connection
	var record lsofRecord

	flush := func() error {
		if record.pid == 0 {
			return nil
		}
		if record.command != "sshd" || (record.hasState && !record.established) {
			record = lsofRecord{}
			return nil
		}
		if !record.hasState {
			record = lsofRecord{}
			return nil
		}

		for _, name := range record.names {
			local, remote, err := parseConnectionName(name)
			if err != nil {
				return fmt.Errorf("parse lsof connection %q: %w", name, err)
			}
			if len(ports) > 0 {
				if _, ok := ports[int(local.Port())]; !ok {
					continue
				}
			}
			connections = append(connections, Connection{
				PID:     record.pid,
				Command: record.command,
				User:    record.user,
				Local:   local,
				Remote:  remote,
				State:   "ESTABLISHED",
			})
		}
		record = lsofRecord{}
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}

		field, value := line[0], line[1:]
		if field == 'p' {
			if err := flush(); err != nil {
				return nil, err
			}
			pid, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse lsof PID %q: %w", value, err)
			}
			record.pid = pid
			continue
		}

		switch field {
		case 'c':
			record.command = value
		case 'u':
			record.user = value
		case 'n':
			record.names = append(record.names, value)
		case 'T':
			record.hasState = true
			record.established = strings.Contains(strings.ToUpper(value), "ESTABLISHED")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read lsof output: %w", err)
	}
	if err := flush(); err != nil {
		return nil, err
	}

	return connections, nil
}

func parseConnectionName(value string) (netip.AddrPort, netip.AddrPort, error) {
	parts := strings.SplitN(value, "->", 2)
	if len(parts) != 2 {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("connection does not contain local and remote endpoints")
	}

	local, err := netip.ParseAddrPort(strings.TrimSpace(parts[0]))
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("parse local endpoint: %w", err)
	}
	remote, err := netip.ParseAddrPort(strings.TrimSpace(parts[1]))
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("parse remote endpoint: %w", err)
	}
	return local, remote, nil
}
