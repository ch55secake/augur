package monitor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ch55secake/augur/internal/config"
)

func TestParseARPOutput(t *testing.T) {
	data := []byte(`? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]
? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.3) at 66:77:88:99:aa:bb on en1 ifscope [ethernet]
`)

	neighbors := parseARPOutput(data)
	if len(neighbors) != 3 {
		t.Fatalf("neighbors = %#v, want three entries", neighbors)
	}
	if neighbors[0].Address.String() != "192.168.1.1" || neighbors[0].MAC != "00:11:22:33:44:55" || neighbors[0].Interface != "en0" {
		t.Fatalf("first neighbor = %#v", neighbors[0])
	}
	if neighbors[1].MAC != "" {
		t.Fatalf("incomplete neighbor MAC = %q, want empty", neighbors[1].MAC)
	}
}

func TestParseNDPOutput(t *testing.T) {
	data := []byte(`Neighbor                             Linklayer Address  Netif Expire  S Flags
fe80::1%en0                         00:11:22:33:44:55  en0   23s     R
fd00::20                            (incomplete)       en0   expired S
`)

	neighbors := parseNDPOutput(data)
	if len(neighbors) != 2 {
		t.Fatalf("neighbors = %#v, want two entries", neighbors)
	}
	if neighbors[0].Address.String() != "fe80::1" || neighbors[0].MAC != "00:11:22:33:44:55" || neighbors[0].Interface != "en0" {
		t.Fatalf("first neighbor = %#v", neighbors[0])
	}
}

func TestExpandProbePrefixesSkipsIPv4NetworkAndBroadcast(t *testing.T) {
	prefix, err := netip.ParsePrefix("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := expandProbePrefixes([]netip.Prefix{prefix}, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{mustAddr(t, "192.168.1.1"), mustAddr(t, "192.168.1.2")}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("addresses = %v, want %v", addresses, want)
	}
}

func TestSystemNetworkProberCombinesNeighborsAndOpenPorts(t *testing.T) {
	runner := &probeRunner{outputs: map[string][][]byte{
		"/usr/sbin/arp": {
			[]byte("? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]\n"),
			[]byte("? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]\n? (192.168.1.2) at 66:77:88:99:aa:bb on en0 ifscope [ethernet]\n"),
		},
		"/usr/sbin/ndp": {[]byte{}, []byte{}},
	}}
	dialer := &probeDialer{open: map[string]bool{"192.168.1.2:22": true}}
	prober := &SystemNetworkProber{
		Runner: runner,
		Dialer: dialer,
		Now:    func() time.Time { return time.Unix(100, 0) },
	}
	prefix, err := netip.ParsePrefix("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}

	observations, err := prober.Probe(context.Background(), []netip.Prefix{prefix}, config.NetworkProbeConfig{
		Enabled:     true,
		Timeout:     config.Duration{Duration: time.Second},
		Concurrency: 2,
		MaxHosts:    4,
		TCPPorts:    []int{22, 80},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []NetworkObservation{{
		Address:    mustAddr(t, "192.168.1.1"),
		MAC:        "00:11:22:33:44:55",
		Interface:  "en0",
		ObservedAt: time.Unix(100, 0),
	}, {
		Address:    mustAddr(t, "192.168.1.2"),
		MAC:        "66:77:88:99:aa:bb",
		Interface:  "en0",
		OpenPorts:  []int{22},
		ObservedAt: time.Unix(100, 0),
	}}
	if !reflect.DeepEqual(observations, want) {
		t.Fatalf("observations = %#v, want %#v", observations, want)
	}
	if calls := dialer.callCount(); calls != 4 {
		t.Fatalf("TCP calls = %d, want four calls", calls)
	}
}

func TestSystemNetworkProberAddsNmapOSFingerprint(t *testing.T) {
	runner := &probeRunner{outputs: map[string][][]byte{
		"/usr/sbin/arp": {
			[]byte("? (192.168.1.2) at 66:77:88:99:aa:bb on en0 ifscope [ethernet]\n"),
			[]byte("? (192.168.1.2) at 66:77:88:99:aa:bb on en0 ifscope [ethernet]\n"),
		},
		"/usr/sbin/ndp": {[]byte{}, []byte{}},
		"nmap": {[]byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.2" addrtype="ipv4"/>
    <os>
      <osmatch name="Apple macOS 14.0" accuracy="96">
        <osclass vendor="Apple" osfamily="Mac OS X" osgen="14.X" accuracy="97">
          <cpe>cpe:/o:apple:mac_os_x:14</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>`)},
	}}
	dialer := &probeDialer{open: map[string]bool{"192.168.1.2:22": true}}
	prober := &SystemNetworkProber{Runner: runner, Dialer: dialer}
	prefix, err := netip.ParsePrefix("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}

	observations, err := prober.Probe(context.Background(), []netip.Prefix{prefix}, config.NetworkProbeConfig{
		Enabled:     true,
		Timeout:     config.Duration{Duration: time.Second},
		Concurrency: 1,
		MaxHosts:    4,
		TCPPorts:    []int{80, 22},
		OSDetection: config.OSDetectionConfig{Enabled: true, Binary: "nmap", Timeout: config.Duration{Duration: time.Second}, MaxHosts: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].OS == nil {
		t.Fatalf("observations = %#v, want one OS fingerprint", observations)
	}
	got := observations[0].OS
	if got.Name != "Apple macOS 14.0" || got.Accuracy != 97 || got.Vendor != "Apple" || got.Family != "Mac OS X" || got.Generation != "14.X" || !reflect.DeepEqual(got.CPEs, []string{"cpe:/o:apple:mac_os_x:14"}) {
		t.Fatalf("OS fingerprint = %#v", got)
	}
	args := strings.Join(runner.args["nmap"], " ")
	for _, want := range []string{"-O", "--osscan-limit", "--max-os-tries 1", "-oX -", "-p 22,80", "192.168.1.2"} {
		if !strings.Contains(args, want) {
			t.Fatalf("nmap args = %q, missing %q", args, want)
		}
	}
}

func TestSystemNetworkProberKeepsInventoryWhenNmapFails(t *testing.T) {
	runner := &probeRunner{
		outputs: map[string][][]byte{
			"/usr/sbin/arp": {
				[]byte("? (192.168.1.2) at 66:77:88:99:aa:bb on en0 ifscope [ethernet]\n"),
				[]byte("? (192.168.1.2) at 66:77:88:99:aa:bb on en0 ifscope [ethernet]\n"),
			},
			"/usr/sbin/ndp": {[]byte{}, []byte{}},
		},
		errors: map[string]error{"nmap": errors.New("nmap not installed")},
	}
	prober := &SystemNetworkProber{Runner: runner, Dialer: &probeDialer{open: map[string]bool{"192.168.1.2:22": true}}}
	prefix, err := netip.ParsePrefix("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}

	observations, err := prober.Probe(context.Background(), []netip.Prefix{prefix}, config.NetworkProbeConfig{
		Enabled:     true,
		Timeout:     config.Duration{Duration: time.Second},
		Concurrency: 1,
		MaxHosts:    4,
		TCPPorts:    []int{22},
		OSDetection: config.OSDetectionConfig{Enabled: true, Binary: "nmap", Timeout: config.Duration{Duration: time.Second}, MaxHosts: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].OS != nil || len(observations[0].OpenPorts) != 1 {
		t.Fatalf("observations = %#v, want base inventory without OS data", observations)
	}
}

func TestSystemNetworkProberReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	prober := &SystemNetworkProber{
		Runner: &probeRunner{outputs: map[string][][]byte{
			"/usr/sbin/arp": {[]byte{}},
			"/usr/sbin/ndp": {[]byte{}},
		}},
		Dialer: &probeDialer{},
	}
	prefix, err := netip.ParsePrefix("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	_, err = prober.Probe(ctx, []netip.Prefix{prefix}, config.NetworkProbeConfig{
		Enabled:     true,
		Timeout:     config.Duration{Duration: time.Second},
		Concurrency: 1,
		MaxHosts:    4,
		TCPPorts:    []int{22},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func TestSystemNetworkProberRejectsOffLinkNetwork(t *testing.T) {
	prefix, err := netip.ParsePrefix("192.168.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	localPrefix, err := netip.ParsePrefix("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	prober := &SystemNetworkProber{
		Runner: &probeRunner{},
		Dialer: &probeDialer{},
		LocalPrefixes: func() ([]netip.Prefix, error) {
			return []netip.Prefix{localPrefix}, nil
		},
	}
	_, err = prober.Probe(context.Background(), []netip.Prefix{prefix}, config.NetworkProbeConfig{
		Enabled:     true,
		Timeout:     config.Duration{Duration: time.Second},
		Concurrency: 1,
		MaxHosts:    4,
		TCPPorts:    []int{22},
	})
	if err == nil || !strings.Contains(err.Error(), "not a local interface subnet") {
		t.Fatalf("error = %v, want off-link error", err)
	}
}

type probeRunner struct {
	outputs map[string][][]byte
	errors  map[string]error
	calls   map[string]int
	args    map[string][]string
}

func (r *probeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if r.calls == nil {
		r.calls = make(map[string]int)
	}
	if r.args == nil {
		r.args = make(map[string][]string)
	}
	r.args[name] = append([]string(nil), args...)
	index := r.calls[name]
	r.calls[name]++
	if err := r.errors[name]; err != nil {
		return nil, err
	}
	outputs := r.outputs[name]
	if index >= len(outputs) {
		return nil, nil
	}
	return outputs[index], nil
}

type probeDialer struct {
	open  map[string]bool
	calls []string
	mu    sync.Mutex
}

func (d *probeDialer) DialContext(_ context.Context, _ string, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, address)
	d.mu.Unlock()
	if !d.open[address] {
		return nil, errors.New("connection refused")
	}
	connection, _ := net.Pipe()
	return connection, nil
}

func (d *probeDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func mustAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}
