# Agent Instructions

## Project

- This is the Go module `github.com/ch55secake/augur`, targeting Go `1.26.5`.
- The intended program is a launchd service that watches active SSH connections and terminates unrecognized ones.
- The executable entrypoint is `cmd/augur`; connection discovery, enforcement, and orchestration live under `internal/monitor`, and JSON configuration lives under `internal/config`.
- SSH device recognition uses public-key fingerprints from root-controlled OpenSSH verbose authentication logs; missing or non-key authentication is unrecognized.
- `packaging/com.ch55secake.augur.plist` is a root LaunchDaemon definition; it is not a per-user LaunchAgent.

## Verification

- Run `go mod tidy` after changing module dependencies.
- Run `make build` and `make test` for build and test verification; these wrap the commands used by shared CI.
- Use `nix develop` for the flake-provided Go development shell and `nix flake check --no-build` to evaluate flake outputs.
- The Makefile provides `make build`, `make test`, `make tidy`, `make check`, and `make dev-shell` equivalents.
- Shared CI also runs golangci-lint and govulncheck through `ch55secake/cheesecake-factory`; do not duplicate those workflows locally.

## GitHub Automation

- `.github/workflows/ci.yml` calls the factory's reusable Go build/test, lint, and vulnerability workflows.
- `.github/workflows/pr-labeler.yml` uses `pull_request_target` because labeling requires `pull-requests: write`; rules are in `.github/labeler.yml`.
- `.github/dependabot.yml` checks the Go module and GitHub Actions daily.
- Labeling expects feature code in `cmd/**` or `internal/**`, tests in `tests/**` or `**/*_test.go`, and documentation in `README.md` or `AGENTS.md`.
