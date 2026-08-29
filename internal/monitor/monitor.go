package monitor

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/ch55secake/augur/internal/config"
)

type Discoverer interface {
	Discover(context.Context) ([]Connection, error)
}

type Enforcer interface {
	Terminate(context.Context, Connection) error
}

type Monitor struct {
	Discoverer       Discoverer
	Enforcer         Enforcer
	IdentityResolver IdentityResolver
	Config           config.Config
	Logger           *slog.Logger
	terminated       map[string]struct{}
}

func New(discoverer Discoverer, enforcer Enforcer, settings config.Config, logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{
		Discoverer: discoverer,
		Enforcer:   enforcer,
		Config:     settings,
		Logger:     logger,
		terminated: make(map[string]struct{}),
	}
}

func (m *Monitor) Run(ctx context.Context) error {
	if m.Config.PollInterval.Duration <= 0 {
		return errors.New("poll interval must be greater than zero")
	}

	ticker := time.NewTicker(m.Config.PollInterval.Duration)
	defer ticker.Stop()

	for {
		if err := m.Scan(ctx); err != nil {
			m.Logger.Error("scan SSH connections", "error", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *Monitor) Scan(ctx context.Context) error {
	if m.Discoverer == nil {
		return &missingDependencyError{name: "discoverer"}
	}

	connections, err := m.Discoverer.Discover(ctx)
	if err != nil {
		return err
	}

	active := make(map[string]struct{}, len(connections))
	for _, connection := range connections {
		key := connection.Key()
		active[key] = struct{}{}
		if m.IdentityResolver != nil {
			identity, err := m.IdentityResolver.Resolve(ctx, connection)
			if err != nil {
				m.Logger.Error("resolve SSH identity", "pid", connection.PID, "error", err)
			} else {
				connection.AuthenticationMethods = identity.AuthenticationMethods
				connection.PublicKeyFingerprints = identity.PublicKeyFingerprints
			}
		}

		network, recognized := m.Config.MatchNetwork(connection.Remote.Addr())
		device, deviceRecognized := m.Config.MatchDevice(connection.User, connection.PublicKeyFingerprints, connection.Remote.Addr())
		m.Logger.Info("active SSH connection",
			"pid", connection.PID,
			"user", connection.User,
			"local_address", connection.Local.String(),
			"remote_address", connection.Remote.String(),
			"network_fingerprint", connection.NetworkFingerprint(),
			"authentication_methods", connection.AuthenticationMethods,
			"key_fingerprints", connection.PublicKeyFingerprints,
			"state", connection.State,
			"recognized", deviceRecognized,
			"network", network.Name,
			"network_recognized", recognized,
			"device", device.Name,
		)

		if deviceRecognized || !m.Config.Enforce {
			continue
		}
		if _, alreadyTerminated := m.terminated[key]; alreadyTerminated {
			continue
		}
		if m.Enforcer == nil {
			return &missingDependencyError{name: "enforcer"}
		}

		m.Logger.Warn("terminating unrecognized SSH connection", "pid", connection.PID, "remote_address", connection.Remote.String(), "key_fingerprints", connection.PublicKeyFingerprints)
		if err := m.Enforcer.Terminate(ctx, connection); err != nil {
			m.Logger.Error("terminate unrecognized SSH connection", "pid", connection.PID, "error", err)
			continue
		}
		m.terminated[key] = struct{}{}
		m.Logger.Info("terminated unrecognized SSH connection", "pid", connection.PID, "remote_address", connection.Remote.String())
	}

	for key := range m.terminated {
		if _, stillActive := active[key]; !stillActive {
			delete(m.terminated, key)
		}
	}
	return nil
}

type missingDependencyError struct {
	name string
}

func (e *missingDependencyError) Error() string {
	return "monitor has no " + e.name
}
