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
	Terminate(context.Context, int) error
}

type Monitor struct {
	Discoverer Discoverer
	Enforcer   Enforcer
	Config     config.Config
	Logger     *slog.Logger
	terminated map[string]struct{}
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

		network, recognized := m.Config.MatchNetwork(connection.Remote.Addr())
		m.Logger.Info("active SSH connection",
			"pid", connection.PID,
			"user", connection.User,
			"local_address", connection.Local.String(),
			"remote_address", connection.Remote.String(),
			"network_fingerprint", connection.NetworkFingerprint(),
			"state", connection.State,
			"recognized", recognized,
			"network", network.Name,
		)

		if recognized || !m.Config.Enforce {
			continue
		}
		if _, alreadyTerminated := m.terminated[key]; alreadyTerminated {
			continue
		}
		if m.Enforcer == nil {
			return &missingDependencyError{name: "enforcer"}
		}

		m.Logger.Warn("terminating unrecognized SSH connection", "pid", connection.PID, "remote_address", connection.Remote.String())
		if err := m.Enforcer.Terminate(ctx, connection.PID); err != nil {
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
