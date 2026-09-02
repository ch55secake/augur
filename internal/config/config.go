package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"
)

const DefaultPath = "/etc/augur/config.json"

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value, err)
	}

	d.Duration = parsed
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

type Network struct {
	Name string `json:"name,omitempty"`
	CIDR string `json:"cidr"`
}

type Device struct {
	Name        string   `json:"name,omitempty"`
	User        string   `json:"user,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Networks    []string `json:"networks,omitempty"`
}

type OSDetectionConfig struct {
	Enabled  bool     `json:"enabled"`
	Binary   string   `json:"binary"`
	Timeout  Duration `json:"timeout"`
	MaxHosts int      `json:"max_hosts"`
}

type NetworkProbeConfig struct {
	Enabled     bool              `json:"enabled"`
	Interval    Duration          `json:"interval"`
	Timeout     Duration          `json:"timeout"`
	Concurrency int               `json:"concurrency"`
	MaxHosts    int               `json:"max_hosts"`
	TCPPorts    []int             `json:"tcp_ports"`
	OSDetection OSDetectionConfig `json:"os_detection"`
}

type Config struct {
	PollInterval  Duration           `json:"poll_interval"`
	SSHPorts      []int              `json:"ssh_ports"`
	Networks      []Network          `json:"recognized_networks"`
	ProbeNetworks []string           `json:"probe_networks,omitempty"`
	NetworkProbes NetworkProbeConfig `json:"network_probes,omitempty"`
	Devices       []Device           `json:"recognized_devices"`
	Enforce       bool               `json:"enforce"`
	LogPath       string             `json:"log_path,omitempty"`
	LogLevel      string             `json:"log_level,omitempty"`
}

func Default() Config {
	return Config{
		PollInterval: Duration{Duration: time.Second},
		SSHPorts:     []int{22},
		NetworkProbes: NetworkProbeConfig{
			Interval:    Duration{Duration: 30 * time.Second},
			Timeout:     Duration{Duration: 500 * time.Millisecond},
			Concurrency: 32,
			MaxHosts:    1024,
			TCPPorts:    []int{22, 80, 443},
			OSDetection: OSDetectionConfig{
				Binary:   "nmap",
				Timeout:  Duration{Duration: 30 * time.Second},
				MaxHosts: 32,
			},
		},
		Enforce:  true,
		LogLevel: "info",
	}
}

func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, errors.New("configuration path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration %q: %w", path, err)
	}

	config, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}

	return config, nil
}

func Parse(data []byte) (Config, error) {
	config := Default()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}

	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Config{}, errors.New("configuration contains more than one JSON value")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("configuration has trailing data: %w", err)
	}

	if err := config.Validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func (c Config) Validate() error {
	if c.PollInterval.Duration <= 0 {
		return errors.New("poll_interval must be greater than zero")
	}
	if len(c.SSHPorts) == 0 {
		return errors.New("ssh_ports must contain at least one port")
	}

	seenPorts := make(map[int]struct{}, len(c.SSHPorts))
	for _, port := range c.SSHPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("ssh port %d is outside the valid range", port)
		}
		if _, exists := seenPorts[port]; exists {
			return fmt.Errorf("ssh port %d is duplicated", port)
		}
		seenPorts[port] = struct{}{}
	}

	networkNames := make(map[string]struct{}, len(c.Networks))
	networkPrefixes := make(map[string]netip.Prefix, len(c.Networks))
	for index, network := range c.Networks {
		prefix, err := ParsePrefix(network.CIDR)
		if err != nil {
			return fmt.Errorf("recognized_networks[%d]: %w", index, err)
		}
		if network.Name == "" {
			continue
		}
		if _, exists := networkNames[network.Name]; exists {
			return fmt.Errorf("recognized_networks[%d]: network name %q is duplicated", index, network.Name)
		}
		networkNames[network.Name] = struct{}{}
		networkPrefixes[network.Name] = prefix
	}

	if err := validateProbeConfig(c, networkNames, networkPrefixes); err != nil {
		return err
	}

	if len(c.Devices) == 0 {
		return errors.New("recognized_devices must contain at least one device")
	}
	for index, device := range c.Devices {
		if !validFingerprint(device.Fingerprint) {
			return fmt.Errorf("recognized_devices[%d]: fingerprint %q is not a SHA256 SSH fingerprint", index, device.Fingerprint)
		}
		for networkIndex, networkName := range device.Networks {
			if strings.TrimSpace(networkName) == "" {
				return fmt.Errorf("recognized_devices[%d].networks[%d]: network name is empty", index, networkIndex)
			}
			if _, exists := networkNames[networkName]; !exists {
				return fmt.Errorf("recognized_devices[%d].networks[%d]: network %q is not defined", index, networkIndex, networkName)
			}
		}
	}

	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q is invalid", c.LogLevel)
	}

	return nil
}

func validateProbeConfig(c Config, networkNames map[string]struct{}, networkPrefixes map[string]netip.Prefix) error {
	for index, name := range c.ProbeNetworks {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("probe_networks[%d]: network name is empty", index)
		}
		if _, exists := networkNames[name]; !exists {
			return fmt.Errorf("probe_networks[%d]: network %q is not defined", index, name)
		}
	}

	settings := c.NetworkProbes
	if settings.OSDetection.Enabled && !settings.Enabled {
		return errors.New("network_probes.os_detection requires network_probes.enabled")
	}
	if !settings.Enabled {
		return nil
	}
	if len(c.ProbeNetworks) == 0 {
		return errors.New("probe_networks must contain at least one network when network probes are enabled")
	}
	if settings.Interval.Duration <= 0 {
		return errors.New("network_probes.interval must be greater than zero")
	}
	if settings.Timeout.Duration <= 0 {
		return errors.New("network_probes.timeout must be greater than zero")
	}
	if settings.Concurrency < 1 || settings.Concurrency > 1024 {
		return errors.New("network_probes.concurrency must be between 1 and 1024")
	}
	if settings.MaxHosts < 1 || settings.MaxHosts > 65536 {
		return errors.New("network_probes.max_hosts must be between 1 and 65536")
	}
	if len(settings.TCPPorts) == 0 {
		return errors.New("network_probes.tcp_ports must contain at least one port")
	}
	if settings.OSDetection.Enabled {
		if strings.TrimSpace(settings.OSDetection.Binary) == "" {
			return errors.New("network_probes.os_detection.binary must not be empty")
		}
		if settings.OSDetection.Timeout.Duration <= 0 {
			return errors.New("network_probes.os_detection.timeout must be greater than zero")
		}
		if settings.OSDetection.Timeout.Duration > 10*time.Minute {
			return errors.New("network_probes.os_detection.timeout must not exceed ten minutes")
		}
		if settings.OSDetection.MaxHosts < 1 || settings.OSDetection.MaxHosts > settings.MaxHosts {
			return fmt.Errorf("network_probes.os_detection.max_hosts must be between 1 and %d", settings.MaxHosts)
		}
	}

	seenPorts := make(map[int]struct{}, len(settings.TCPPorts))
	for _, port := range settings.TCPPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("network probe port %d is outside the valid range", port)
		}
		if _, exists := seenPorts[port]; exists {
			return fmt.Errorf("network probe port %d is duplicated", port)
		}
		seenPorts[port] = struct{}{}
	}

	seenNetworks := make(map[string]struct{}, len(c.ProbeNetworks))
	for _, name := range c.ProbeNetworks {
		if _, exists := seenNetworks[name]; exists {
			return fmt.Errorf("probe network %q is duplicated", name)
		}
		seenNetworks[name] = struct{}{}

		prefix := networkPrefixes[name]
		if !prefix.Addr().IsPrivate() && !prefix.Addr().IsLinkLocalUnicast() {
			return fmt.Errorf("probe network %q must be private or link-local", name)
		}
		if prefixHostCount(prefix, settings.MaxHosts) > settings.MaxHosts {
			return fmt.Errorf("probe network %q contains more than %d hosts", name, settings.MaxHosts)
		}
	}

	return nil
}

func prefixHostCount(prefix netip.Prefix, limit int) int {
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits >= 63 {
		return limit + 1
	}
	count := uint64(1) << uint(hostBits)
	if count > uint64(limit) {
		return limit + 1
	}
	return int(count)
}

func (c Config) ProbePrefixes() ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(c.ProbeNetworks))
	for _, name := range c.ProbeNetworks {
		for _, network := range c.Networks {
			if network.Name != name {
				continue
			}
			prefix, err := ParsePrefix(network.CIDR)
			if err != nil {
				return nil, fmt.Errorf("probe network %q: %w", name, err)
			}
			prefixes = append(prefixes, prefix)
			break
		}
	}
	if len(prefixes) != len(c.ProbeNetworks) {
		return nil, errors.New("probe network configuration contains an undefined network")
	}
	return prefixes, nil
}

func ParsePrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errors.New("network CIDR is empty")
	}

	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}

	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("network %q is not a valid CIDR or IP address", value)
	}

	return netip.PrefixFrom(address, address.BitLen()), nil
}

func (c Config) MatchNetwork(address netip.Addr) (Network, bool) {
	address = address.Unmap()
	for _, network := range c.Networks {
		prefix, err := ParsePrefix(network.CIDR)
		if err == nil && prefix.Contains(address) {
			return network, true
		}
	}

	return Network{}, false
}

func (c Config) MatchDevice(user string, fingerprints []string, address netip.Addr) (Device, bool) {
	address = address.Unmap()
	for _, device := range c.Devices {
		if device.User != "" && device.User != user {
			continue
		}
		if !containsFingerprint(fingerprints, device.Fingerprint) {
			continue
		}
		if !c.deviceMatchesNetwork(device, address) {
			continue
		}
		return device, true
	}

	return Device{}, false
}

func (c Config) deviceMatchesNetwork(device Device, address netip.Addr) bool {
	if len(device.Networks) > 0 {
		for _, name := range device.Networks {
			for _, network := range c.Networks {
				if network.Name != name {
					continue
				}
				prefix, err := ParsePrefix(network.CIDR)
				if err == nil && prefix.Contains(address) {
					return true
				}
			}
		}
		return false
	}

	if len(c.Networks) == 0 {
		return true
	}
	_, recognized := c.MatchNetwork(address)
	return recognized
}

func containsFingerprint(fingerprints []string, want string) bool {
	for _, fingerprint := range fingerprints {
		if fingerprint == want {
			return true
		}
	}
	return false
}

func validFingerprint(value string) bool {
	const prefix = "SHA256:"
	if value != strings.TrimSpace(value) {
		return false
	}
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := strings.TrimPrefix(value, prefix)
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size && base64.RawStdEncoding.EncodeToString(decoded) == encoded
}
