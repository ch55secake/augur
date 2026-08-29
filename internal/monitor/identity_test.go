package monitor

import (
	"context"
	"testing"
	"time"
)

func TestParseAuthLog(t *testing.T) {
	data := []byte(`Filtering the log data using "process == sshd"
 {"timestamp":"2026-08-29 12:00:00.000000+0000","processID":101,"eventMessage":"Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: ED25519 SHA256:trusted-key"}
 {"timestamp":"2026-08-29 12:01:00.000000+0000","processID":102,"eventMessage":"Accepted password for bob from 10.0.0.50 port 54322 ssh2"}
 {"timestamp":"2026-08-29 12:02:00.000000+0000","processID":103,"eventMessage":"Received disconnect from 192.168.1.60 port 54323: 11: disconnected"}
`)

	identities, err := ParseAuthLog(data)
	if err != nil {
		t.Fatal(err)
	}

	publicKeyIdentity, ok := identities["101/192.168.1.50:54321"]
	if !ok {
		t.Fatal("public-key authentication was not indexed")
	}
	if len(publicKeyIdentity.AuthenticationMethods) != 1 || publicKeyIdentity.AuthenticationMethods[0] != "publickey" {
		t.Fatalf("authentication methods = %#v", publicKeyIdentity.AuthenticationMethods)
	}
	if len(publicKeyIdentity.PublicKeyFingerprints) != 1 || publicKeyIdentity.PublicKeyFingerprints[0] != "SHA256:trusted-key" {
		t.Fatalf("key fingerprints = %#v", publicKeyIdentity.PublicKeyFingerprints)
	}

	passwordIdentity, ok := identities["102/10.0.0.50:54322"]
	if !ok {
		t.Fatal("password authentication was not indexed")
	}
	if len(passwordIdentity.PublicKeyFingerprints) != 0 {
		t.Fatalf("password key fingerprints = %#v", passwordIdentity.PublicKeyFingerprints)
	}
}

func TestSystemIdentityResolver(t *testing.T) {
	runner := &identityRunner{
		logOutput:    []byte(`{"timestamp":"2026-08-29 12:00:00.000000+0000","processID":101,"eventMessage":"Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: ED25519 SHA256:trusted-key"}` + "\n"),
		processStart: []byte("Sat 29 Aug 11:59:00 2026\n"),
	}
	resolver := &SystemIdentityResolver{
		Runner: runner,
		Now:    func() time.Time { return time.Unix(100, 0) },
	}

	identity, err := resolver.Resolve(context.Background(), Connection{PID: 101, Remote: mustAddrPort(t, "192.168.1.50:54321")})
	if err != nil {
		t.Fatal(err)
	}
	if len(identity.PublicKeyFingerprints) != 1 || identity.PublicKeyFingerprints[0] != "SHA256:trusted-key" {
		t.Fatalf("key fingerprints = %#v", identity.PublicKeyFingerprints)
	}
	if runner.logCalls != 1 {
		t.Fatalf("log command calls = %d, want 1", runner.logCalls)
	}
}

func TestSystemIdentityResolverCachesLogRefresh(t *testing.T) {
	runner := &identityRunner{
		logOutput:    []byte(`{"timestamp":"2026-08-29 12:00:00.000000+0000","processID":101,"eventMessage":"Accepted password for alice from 192.168.1.50 port 54321 ssh2"}` + "\n"),
		processStart: []byte("Sat 29 Aug 11:59:00 2026\n"),
	}
	current := time.Unix(100, 0)
	resolver := &SystemIdentityResolver{Runner: runner, Now: func() time.Time { return current }}
	connection := Connection{PID: 101, Remote: mustAddrPort(t, "192.168.1.50:54321")}

	if _, err := resolver.Resolve(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	current = current.Add(500 * time.Millisecond)
	if _, err := resolver.Resolve(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if runner.logCalls != 1 {
		t.Fatalf("log command calls = %d, want 1", runner.logCalls)
	}
}

func TestSystemIdentityResolverRejectsRecordFromEarlierProcess(t *testing.T) {
	runner := &identityRunner{
		logOutput:    []byte(`{"timestamp":"2026-08-29 12:00:00.000000+0000","processID":101,"eventMessage":"Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: ED25519 SHA256:trusted-key"}` + "\n"),
		processStart: []byte("Sat 29 Aug 13:01:00 2026\n"),
	}
	resolver := &SystemIdentityResolver{Runner: runner, Now: func() time.Time { return time.Unix(100, 0) }}

	identity, err := resolver.Resolve(context.Background(), Connection{PID: 101, Remote: mustAddrPort(t, "192.168.1.50:54321")})
	if err != nil {
		t.Fatal(err)
	}
	if len(identity.PublicKeyFingerprints) != 0 {
		t.Fatalf("stale key fingerprints = %#v", identity.PublicKeyFingerprints)
	}
}

type identityRunner struct {
	logOutput    []byte
	processStart []byte
	logCalls     int
}

func (r *identityRunner) Run(_ context.Context, name string, _ ...string) ([]byte, error) {
	switch name {
	case "/usr/bin/log":
		r.logCalls++
		return r.logOutput, nil
	case "ps":
		return r.processStart, nil
	default:
		return nil, nil
	}
}
