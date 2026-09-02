package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	config, err := Parse([]byte(`{
        "poll_interval": "2s",
        "ssh_ports": [22, 2222],
        "recognized_networks": [{"name": "lan", "cidr": "192.168.1.0/24"}],
		"probe_networks": ["lan"],
		"network_probes": {"enabled": true, "interval": "30s", "timeout": "500ms", "concurrency": 8, "max_hosts": 256, "tcp_ports": [22, 443], "os_detection": {"enabled": true, "binary": "nmap", "timeout": "20s", "max_hosts": 2}},
        "recognized_devices": [{"name": "laptop", "user": "501", "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}],
        "enforce": true,
        "log_level": "debug"
    }`))
	if err != nil {
		t.Fatal(err)
	}

	if config.PollInterval.Duration != 2*time.Second {
		t.Fatalf("poll interval = %s, want 2s", config.PollInterval.Duration)
	}
	if network, ok := config.MatchNetwork(mustAddr(t, "192.168.1.109")); !ok || network.Name != "lan" {
		t.Fatalf("network match = %#v, %t", network, ok)
	}
	prefixes, err := config.ProbePrefixes()
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 1 || prefixes[0].String() != "192.168.1.0/24" {
		t.Fatalf("probe prefixes = %v", prefixes)
	}
	if config.NetworkProbes.OSDetection.Timeout.Duration != 20*time.Second || config.NetworkProbes.OSDetection.MaxHosts != 2 {
		t.Fatalf("OS detection config = %#v", config.NetworkProbes.OSDetection)
	}
}

func TestParseDefaultsEnforce(t *testing.T) {
	config, err := Parse([]byte(`{
		"recognized_networks": [{"cidr": "10.0.0.0/8"}],
		"recognized_devices": [{"fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enforce {
		t.Fatal("enforce defaulted to false")
	}
}

func TestMatchDevice(t *testing.T) {
	settings := Config{
		Networks: []Network{{Name: "trusted", CIDR: "192.168.1.0/24"}},
		Devices: []Device{{
			Name:        "laptop",
			User:        "501",
			Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		}},
	}

	device, ok := settings.MatchDevice("501", []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, mustAddr(t, "192.168.1.50"))
	if !ok || device.Name != "laptop" {
		t.Fatalf("device match = %#v, %t", device, ok)
	}
	if _, ok := settings.MatchDevice("502", []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, mustAddr(t, "192.168.1.50")); ok {
		t.Fatal("matched device for the wrong user")
	}
	if _, ok := settings.MatchDevice("501", []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, mustAddr(t, "10.0.0.50")); ok {
		t.Fatal("matched device outside the recognized network")
	}
}

func TestMatchDeviceNetworkRestriction(t *testing.T) {
	settings := Config{
		Networks: []Network{
			{Name: "lan", CIDR: "192.168.1.0/24"},
			{Name: "vpn", CIDR: "10.0.0.0/8"},
		},
		Devices: []Device{{
			Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Networks:    []string{"vpn"},
		}},
	}

	if _, ok := settings.MatchDevice("", []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, mustAddr(t, "192.168.1.50")); ok {
		t.Fatal("matched device outside its configured networks")
	}
	if _, ok := settings.MatchDevice("", []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, mustAddr(t, "10.0.0.50")); !ok {
		t.Fatal("did not match device in its configured network")
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "no devices",
			data: `{"recognized_networks": [{"cidr": "10.0.0.0/8"}]}`,
			want: "recognized_devices",
		},
		{
			name: "invalid port",
			data: `{"ssh_ports": [0], "recognized_networks": [{"cidr": "10.0.0.0/8"}], "recognized_devices": [{"fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
			want: "outside the valid range",
		},
		{
			name: "unknown field",
			data: `{"recognized_networks": [{"cidr": "10.0.0.0/8"}], "recognized_devices": [{"fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}], "unknown": true}`,
			want: "unknown field",
		},
		{
			name: "trailing data",
			data: `{"recognized_networks": [{"cidr": "10.0.0.0/8"}], "recognized_devices": [{"fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]} true`,
			want: "more than one",
		},
		{
			name: "invalid fingerprint",
			data: `{"recognized_devices": [{"fingerprint": "ssh-ed25519"}]}`,
			want: "SHA256 SSH fingerprint",
		},
		{
			name: "unknown device network",
			data: `{"recognized_networks": [{"name": "lan", "cidr": "10.0.0.0/8"}], "recognized_devices": [{"fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "networks": ["vpn"]}]}`,
			want: "is not defined",
		},
		{
			name: "enabled probes without targets",
			data: `{"recognized_networks": [{"name": "lan", "cidr": "10.0.0.0/24"}], "network_probes": {"enabled": true}}`,
			want: "probe_networks must contain",
		},
		{
			name: "probe target must be defined",
			data: `{"recognized_networks": [{"name": "lan", "cidr": "10.0.0.0/24"}], "probe_networks": ["vpn"]}`,
			want: "is not defined",
		},
		{
			name: "probe target must be private",
			data: `{"recognized_networks": [{"name": "wan", "cidr": "203.0.113.0/24"}], "probe_networks": ["wan"], "network_probes": {"enabled": true}}`,
			want: "private or link-local",
		},
		{
			name: "probe target is bounded",
			data: `{"recognized_networks": [{"name": "lan", "cidr": "10.0.0.0/8"}], "probe_networks": ["lan"], "network_probes": {"enabled": true}}`,
			want: "more than",
		},
		{
			name: "probe port is invalid",
			data: `{"recognized_networks": [{"name": "lan", "cidr": "10.0.0.0/24"}], "probe_networks": ["lan"], "network_probes": {"enabled": true, "tcp_ports": [0]}}`,
			want: "outside the valid range",
		},
		{
			name: "OS detection requires probes",
			data: `{"recognized_networks": [{"name": "lan", "cidr": "10.0.0.0/24"}], "probe_networks": ["lan"], "network_probes": {"os_detection": {"enabled": true}}}`,
			want: "requires network_probes.enabled",
		},
		{
			name: "OS detection host limit is bounded",
			data: `{"recognized_networks": [{"name": "lan", "cidr": "10.0.0.0/24"}], "probe_networks": ["lan"], "network_probes": {"enabled": true, "os_detection": {"enabled": true, "max_hosts": 2048}}}`,
			want: "between 1 and 1024",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.data))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func mustAddr(t *testing.T, value string) (address netip.Addr) {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}
