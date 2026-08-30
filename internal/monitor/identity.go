package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type SSHIdentity struct {
	AuthenticationMethods []string
	PublicKeyFingerprints []string
}

type IdentityResolver interface {
	Resolve(context.Context, Connection) (SSHIdentity, error)
}

type SystemIdentityResolver struct {
	Runner      CommandRunner
	Now         func() time.Time
	lastRefresh time.Time
	lastError   error
	identities  map[string]authLogRecord
}

type authLogRecord struct {
	Identity  SSHIdentity
	Timestamp time.Time
}

func NewSystemIdentityResolver(runner CommandRunner) *SystemIdentityResolver {
	return &SystemIdentityResolver{Runner: runner, Now: time.Now}
}

func (r *SystemIdentityResolver) Resolve(ctx context.Context, connection Connection) (SSHIdentity, error) {
	if err := r.refresh(ctx); err != nil {
		return SSHIdentity{}, err
	}
	record, ok := r.identities[sessionKey(connection.PID, connection.Remote)]
	if !ok {
		return SSHIdentity{}, nil
	}
	processStart, err := r.processStart(ctx, connection.PID)
	if err != nil {
		return SSHIdentity{}, err
	}
	if record.Timestamp.Before(processStart) {
		return SSHIdentity{}, nil
	}
	return record.Identity, nil
}

func (r *SystemIdentityResolver) refresh(ctx context.Context) error {
	if r.Runner == nil {
		return fmt.Errorf("identity resolver has no command runner")
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	if !r.lastRefresh.IsZero() && now.Sub(r.lastRefresh) < time.Second {
		return r.lastError
	}
	r.lastRefresh = now

	output, err := r.Runner.Run(ctx, "/usr/bin/log", "show", "--style", "ndjson", "--info", "--last", "5m", "--predicate", `process == "sshd" OR process == "sshd-session"`)
	if err != nil {
		r.lastError = fmt.Errorf("read SSH authentication log: %w", err)
		return r.lastError
	}

	identities, err := parseAuthLogRecords(output)
	if err != nil {
		r.lastError = fmt.Errorf("parse SSH authentication log: %w", err)
		return r.lastError
	}
	if r.identities == nil {
		r.identities = make(map[string]authLogRecord)
	}
	for key, identity := range identities {
		r.identities[key] = identity
	}
	r.lastError = nil
	return nil
}

func ParseAuthLog(data []byte) (map[string]SSHIdentity, error) {
	records, err := parseAuthLogRecords(data)
	if err != nil {
		return nil, err
	}
	identities := make(map[string]SSHIdentity, len(records))
	for key, record := range records {
		identities[key] = record.Identity
	}
	return identities, nil
}

func parseAuthLogRecords(data []byte) (map[string]authLogRecord, error) {
	identities := make(map[string]authLogRecord)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var event struct {
			EventMessage string `json:"eventMessage"`
			ProcessID    int    `json:"processID"`
			Timestamp    string `json:"timestamp"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("decode log event: %w", err)
		}
		remote, identity, ok := parseAcceptedEvent(event.EventMessage)
		if ok && event.ProcessID > 0 {
			timestamp, err := parseLogTimestamp(event.Timestamp)
			if err == nil {
				identities[sessionKey(event.ProcessID, remote)] = authLogRecord{Identity: identity, Timestamp: timestamp}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read log events: %w", err)
	}
	return identities, nil
}

func (r *SystemIdentityResolver) processStart(ctx context.Context, pid int) (time.Time, error) {
	output, err := r.Runner.Run(ctx, "ps", "-p", fmt.Sprint(pid), "-o", "lstart=")
	if err != nil {
		return time.Time{}, fmt.Errorf("read start time for PID %d: %w", pid, err)
	}
	start, err := time.ParseInLocation("Mon 02 Jan 15:04:05 2006", strings.TrimSpace(string(output)), time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse start time for PID %d: %w", pid, err)
	}
	return start, nil
}

func parseLogTimestamp(value string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999-0700",
		time.RFC3339Nano,
	} {
		if timestamp, err := time.Parse(layout, value); err == nil {
			return timestamp, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", value)
}

func parseAcceptedEvent(message string) (netip.AddrPort, SSHIdentity, bool) {
	fields := strings.Fields(message)
	if len(fields) < 8 || fields[0] != "Accepted" || fields[2] != "for" || fields[4] != "from" || fields[6] != "port" {
		return netip.AddrPort{}, SSHIdentity{}, false
	}

	address, err := netip.ParseAddr(fields[5])
	if err != nil {
		return netip.AddrPort{}, SSHIdentity{}, false
	}
	port, err := strconv.ParseUint(fields[7], 10, 16)
	if err != nil {
		return netip.AddrPort{}, SSHIdentity{}, false
	}

	identity := SSHIdentity{AuthenticationMethods: []string{fields[1]}}
	if fields[1] == "publickey" {
		for _, field := range fields[8:] {
			if strings.HasPrefix(field, "SHA256:") {
				identity.PublicKeyFingerprints = append(identity.PublicKeyFingerprints, field)
				break
			}
		}
	}

	return netip.AddrPortFrom(address.Unmap(), uint16(port)), identity, true
}

func sessionKey(pid int, remote netip.AddrPort) string {
	return fmt.Sprintf("%d/%s", pid, remote.String())
}
