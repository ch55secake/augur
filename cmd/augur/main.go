package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ch55secake/augur/internal/config"
	"github.com/ch55secake/augur/internal/monitor"
)

func main() {
	configPath := flag.String("config", config.DefaultPath, "path to the JSON configuration file")
	once := flag.Bool("once", false, "scan once and exit")
	dryRun := flag.Bool("dry-run", false, "log unrecognized connections without terminating them")
	flag.Parse()

	settings, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load configuration", "error", err)
		os.Exit(1)
	}

	logger, closeLog, err := newLogger(settings)
	if err != nil {
		slog.Error("open log", "error", err)
		os.Exit(1)
	}
	defer closeLog()

	if *dryRun {
		settings.Enforce = false
		logger.Warn("dry-run mode enabled")
	}

	runner := monitor.ExecRunner{}
	discoverer := monitor.NewLsofDiscoverer(runner, settings.SSHPorts)
	enforcer := monitor.TreeTerminator{
		Processes:   monitor.SystemProcessController{Runner: runner},
		Connections: monitor.NewLsofConnectionVerifier(runner),
	}
	service := monitor.New(discoverer, enforcer, settings, logger)
	service.IdentityResolver = monitor.NewSystemIdentityResolver(runner)
	service.NetworkProber = monitor.NewSystemNetworkProber(runner)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("augur started", "config", *configPath, "enforce", settings.Enforce, "poll_interval", settings.PollInterval.String())
	if *once {
		if err := service.Scan(ctx); err != nil {
			logger.Error("scan SSH connections", "error", err)
			os.Exit(1)
		}
		return
	}

	if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("augur stopped", "error", err)
		os.Exit(1)
	}
}

func newLogger(settings config.Config) (*slog.Logger, func(), error) {
	var writer io.Writer = os.Stderr
	closeWriter := func() {}

	if settings.LogPath != "" {
		file, err := os.OpenFile(settings.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open log path %q: %w", settings.LogPath, err)
		}
		writer = file
		closeWriter = func() { _ = file.Close() }
	}

	level := slog.LevelInfo
	switch strings.ToLower(settings.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level})), closeWriter, nil
}
