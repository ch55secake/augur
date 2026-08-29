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
}

func TestParseDefaultsEnforce(t *testing.T) {
	config, err := Parse([]byte(`{
        "recognized_networks": [{"cidr": "10.0.0.0/8"}]
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enforce {
		t.Fatal("enforce defaulted to false")
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "no networks",
			data: `{"recognized_networks": []}`,
			want: "recognized_networks",
		},
		{
			name: "invalid port",
			data: `{"ssh_ports": [0], "recognized_networks": [{"cidr": "10.0.0.0/8"}]}`,
			want: "outside the valid range",
		},
		{
			name: "unknown field",
			data: `{"recognized_networks": [{"cidr": "10.0.0.0/8"}], "unknown": true}`,
			want: "unknown field",
		},
		{
			name: "trailing data",
			data: `{"recognized_networks": [{"cidr": "10.0.0.0/8"}]} true`,
			want: "more than one",
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
