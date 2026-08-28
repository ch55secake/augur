package config

import (
	"bytes"
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

type Config struct {
	PollInterval Duration  `json:"poll_interval"`
	SSHPorts     []int     `json:"ssh_ports"`
	Networks     []Network `json:"recognized_networks"`
	Enforce      bool      `json:"enforce"`
	LogPath      string    `json:"log_path,omitempty"`
	LogLevel     string    `json:"log_level,omitempty"`
}

func Default() Config {
	return Config{
		PollInterval: Duration{Duration: time.Second},
		SSHPorts:     []int{22},
		Enforce:      true,
		LogLevel:     "info",
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

	if len(c.Networks) == 0 {
		return errors.New("recognized_networks must contain at least one network")
	}
	for index, network := range c.Networks {
		if _, err := ParsePrefix(network.CIDR); err != nil {
			return fmt.Errorf("recognized_networks[%d]: %w", index, err)
		}
	}

	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q is invalid", c.LogLevel)
	}

	return nil
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
