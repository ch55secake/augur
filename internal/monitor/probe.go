package monitor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ch55secake/augur/internal/config"
)

type NetworkObservation struct {
	Address    netip.Addr `json:"address"`
	MAC        string     `json:"mac,omitempty"`
	Interface  string     `json:"interface,omitempty"`
	OpenPorts  []int      `json:"open_ports,omitempty"`
	ObservedAt time.Time  `json:"observed_at"`
}

type NetworkProber interface {
	Probe(context.Context, []netip.Prefix, config.NetworkProbeConfig) ([]NetworkObservation, error)
}

type NetworkDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type SystemNetworkProber struct {
	Runner        CommandRunner
	Dialer        NetworkDialer
	LocalPrefixes func() ([]netip.Prefix, error)
	Now           func() time.Time
}

func NewSystemNetworkProber(runner CommandRunner) *SystemNetworkProber {
	return &SystemNetworkProber{
		Runner:        runner,
		Dialer:        &net.Dialer{},
		LocalPrefixes: localInterfacePrefixes,
		Now:           time.Now,
	}
}

type networkNeighbor struct {
	Address   netip.Addr
	MAC       string
	Interface string
	OpenPorts []int
}

func (p *SystemNetworkProber) Probe(ctx context.Context, prefixes []netip.Prefix, settings config.NetworkProbeConfig) ([]NetworkObservation, error) {
	if !settings.Enabled {
		return nil, nil
	}
	if p == nil || p.Runner == nil {
		return nil, errors.New("network prober has no command runner")
	}
	if p.Dialer == nil {
		return nil, errors.New("network prober has no network dialer")
	}
	if settings.MaxHosts < 1 {
		return nil, errors.New("network probe max hosts must be greater than zero")
	}
	if p.LocalPrefixes != nil {
		localPrefixes, err := p.LocalPrefixes()
		if err != nil {
			return nil, fmt.Errorf("load local interface prefixes: %w", err)
		}
		if err := validateLocalProbePrefixes(prefixes, localPrefixes); err != nil {
			return nil, err
		}
	}

	before, err := readNeighbors(ctx, p.Runner)
	if err != nil {
		return nil, err
	}
	targets, err := expandProbePrefixes(prefixes, settings.MaxHosts)
	if err != nil {
		return nil, err
	}
	openPorts, err := p.scanTCP(ctx, targets, settings)
	if err != nil {
		return nil, err
	}
	after, err := readNeighbors(ctx, p.Runner)
	if err != nil {
		return nil, err
	}

	observedAt := time.Now()
	if p.Now != nil {
		observedAt = p.Now()
	}
	return combineObservations(prefixes, before, after, openPorts, observedAt), nil
}

func (p *SystemNetworkProber) scanTCP(ctx context.Context, targets []netip.Addr, settings config.NetworkProbeConfig) (map[netip.Addr][]int, error) {
	if len(targets) == 0 {
		return map[netip.Addr][]int{}, nil
	}
	workerCount := settings.Concurrency
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(targets) {
		workerCount = len(targets)
	}

	type result struct {
		address netip.Addr
		ports   []int
	}
	jobs := make(chan netip.Addr)
	results := make(chan result, workerCount)

	go func() {
		defer close(jobs)
		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()

	workersDone := make(chan struct{})
	for index := 0; index < workerCount; index++ {
		go func() {
			defer func() { workersDone <- struct{}{} }()
			for target := range jobs {
				ports := p.probeAddress(ctx, target, settings)
				select {
				case results <- result{address: target, ports: ports}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		for index := 0; index < workerCount; index++ {
			<-workersDone
		}
		close(results)
	}()

	openPorts := make(map[netip.Addr][]int)
	for result := range results {
		if len(result.ports) > 0 {
			openPorts[result.address] = result.ports
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openPorts, nil
}

func (p *SystemNetworkProber) probeAddress(ctx context.Context, address netip.Addr, settings config.NetworkProbeConfig) []int {
	network := "tcp6"
	if address.Is4() {
		network = "tcp4"
	}
	ports := make([]int, 0, len(settings.TCPPorts))
	for _, port := range settings.TCPPorts {
		if ctx.Err() != nil {
			return ports
		}
		probeContext, cancel := context.WithTimeout(ctx, settings.Timeout.Duration)
		connection, err := p.Dialer.DialContext(probeContext, network, net.JoinHostPort(address.String(), strconv.Itoa(port)))
		cancel()
		if err != nil {
			continue
		}
		if connection != nil {
			_ = connection.Close()
		}
		ports = append(ports, port)
	}
	return ports
}

func expandProbePrefixes(prefixes []netip.Prefix, maxHosts int) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0)
	seen := make(map[netip.Addr]struct{})
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		hostBits := prefix.Addr().BitLen() - prefix.Bits()
		if hostBits >= 63 {
			return nil, fmt.Errorf("probe network %s is too large", prefix)
		}
		count := uint64(1) << uint(hostBits)
		if count > uint64(maxHosts) {
			return nil, fmt.Errorf("probe network %s contains more than %d hosts", prefix, maxHosts)
		}

		address := prefix.Addr()
		for index := uint64(0); index < count; index++ {
			if prefix.Addr().Is4() && count > 2 && (index == 0 || index == count-1) {
				address = address.Next()
				continue
			}
			if _, exists := seen[address]; !exists {
				seen[address] = struct{}{}
				addresses = append(addresses, address)
			}
			address = address.Next()
		}
	}
	return addresses, nil
}

func localInterfacePrefixes() ([]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var prefixes []netip.Prefix
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("read addresses for %s: %w", networkInterface.Name, err)
		}
		for _, address := range addresses {
			var ip net.IP
			var mask net.IPMask
			switch value := address.(type) {
			case *net.IPNet:
				ip, mask = value.IP, value.Mask
			case *net.IPAddr:
				ip = value.IP
			default:
				continue
			}
			parsed, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			if mask == nil {
				prefixes = append(prefixes, netip.PrefixFrom(parsed.Unmap(), parsed.BitLen()))
				continue
			}
			bits, size := mask.Size()
			if bits == 0 && size == 0 {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(parsed.Unmap(), bits).Masked())
		}
	}
	if len(prefixes) == 0 {
		return nil, errors.New("no local interface prefixes found")
	}
	return prefixes, nil
}

func validateLocalProbePrefixes(probePrefixes, localPrefixes []netip.Prefix) error {
	for _, probePrefix := range probePrefixes {
		probePrefix = probePrefix.Masked()
		local := false
		for _, localPrefix := range localPrefixes {
			localPrefix = localPrefix.Masked()
			if localPrefix.Addr().BitLen() != probePrefix.Addr().BitLen() || localPrefix.Bits() > probePrefix.Bits() {
				continue
			}
			if localPrefix.Contains(probePrefix.Addr()) {
				local = true
				break
			}
		}
		if !local {
			return fmt.Errorf("probe network %s is not a local interface subnet", probePrefix)
		}
	}
	return nil
}

func readNeighbors(ctx context.Context, runner CommandRunner) ([]networkNeighbor, error) {
	commands := []struct {
		name   string
		args   []string
		parser func([]byte) []networkNeighbor
	}{
		{name: "/usr/sbin/arp", args: []string{"-an"}, parser: parseARPOutput},
		{name: "/usr/sbin/ndp", args: []string{"-an"}, parser: parseNDPOutput},
	}

	var neighbors []networkNeighbor
	for _, command := range commands {
		output, err := runner.Run(ctx, command.name, command.args...)
		if err != nil {
			var exitError *exec.ExitError
			if errors.As(err, &exitError) && exitError.ExitCode() == 1 && len(strings.TrimSpace(string(output))) == 0 {
				continue
			}
			return nil, fmt.Errorf("run %s: %w", command.name, err)
		}
		neighbors = append(neighbors, command.parser(output)...)
	}
	return neighbors, nil
}

func parseARPOutput(data []byte) []networkNeighbor {
	var neighbors []networkNeighbor
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		open := strings.IndexByte(line, '(')
		close := strings.IndexByte(line, ')')
		if open < 0 || close <= open {
			continue
		}
		address, ok := parseNeighborAddress(line[open+1 : close])
		if !ok {
			continue
		}

		var macAddress, interfaceName string
		fields := strings.Fields(line[close+1:])
		for index, field := range fields {
			switch field {
			case "at":
				if index+1 < len(fields) {
					macAddress = normalizeMAC(fields[index+1])
				}
			case "on":
				if index+1 < len(fields) {
					interfaceName = fields[index+1]
				}
			}
		}
		neighbors = append(neighbors, networkNeighbor{Address: address, MAC: macAddress, Interface: interfaceName})
	}
	return neighbors
}

func parseNDPOutput(data []byte) []networkNeighbor {
	var neighbors []networkNeighbor
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		address, ok := parseNeighborAddress(fields[0])
		if !ok {
			continue
		}
		macAddress := normalizeMAC(fields[1])
		interfaceName := ""
		if len(fields) > 2 {
			interfaceName = fields[2]
		}
		neighbors = append(neighbors, networkNeighbor{Address: address, MAC: macAddress, Interface: interfaceName})
	}
	return neighbors
}

func parseNeighborAddress(value string) (netip.Addr, bool) {
	if zoneIndex := strings.LastIndexByte(value, '%'); zoneIndex >= 0 {
		value = value[:zoneIndex]
	}
	address, err := netip.ParseAddr(value)
	return address.Unmap(), err == nil
}

func normalizeMAC(value string) string {
	if strings.EqualFold(value, "incomplete") || strings.EqualFold(value, "(incomplete)") {
		return ""
	}
	address, err := net.ParseMAC(strings.Trim(value, "()"))
	if err != nil {
		return ""
	}
	return address.String()
}

func combineObservations(prefixes []netip.Prefix, before, after []networkNeighbor, openPorts map[netip.Addr][]int, observedAt time.Time) []NetworkObservation {
	neighbors := make(map[netip.Addr]networkNeighbor)
	for _, neighbor := range append(before, after...) {
		address := neighbor.Address.Unmap()
		if !containsPrefix(prefixes, address) {
			continue
		}
		current := neighbors[address]
		if current.Address == (netip.Addr{}) {
			current.Address = address
		}
		if neighbor.MAC != "" {
			current.MAC = neighbor.MAC
		}
		if neighbor.Interface != "" {
			current.Interface = neighbor.Interface
		}
		neighbors[address] = current
	}
	for address, ports := range openPorts {
		address = address.Unmap()
		if !containsPrefix(prefixes, address) {
			continue
		}
		current := neighbors[address]
		current.Address = address
		current.OpenPorts = append([]int(nil), ports...)
		neighbors[address] = current
	}

	addresses := make([]netip.Addr, 0, len(neighbors))
	for address := range neighbors {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })

	observations := make([]NetworkObservation, 0, len(addresses))
	for _, address := range addresses {
		neighbor := neighbors[address]
		ports := append([]int(nil), neighbor.OpenPorts...)
		sort.Ints(ports)
		observations = append(observations, NetworkObservation{
			Address:    address,
			MAC:        neighbor.MAC,
			Interface:  neighbor.Interface,
			OpenPorts:  ports,
			ObservedAt: observedAt,
		})
	}
	return observations
}

func containsPrefix(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
