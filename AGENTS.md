# Agent Instructions

## Project

- This is the Go module `github.com/ch55secake/augur`, targeting Go `1.26.5`.
- The intended program is a launchd service that watches active SSH connections and terminates unrecognized ones.
- There are currently no Go packages; commands run from the repository root.

## Verification

- Run `go mod tidy` after changing module dependencies.
- Run `make build` and `make test` for build and test verification; these wrap the commands used by shared CI.
- Use `nix develop` for the flake-provided Go development shell and `nix flake check --no-build` to evaluate flake outputs.
- The Makefile provides `make build`, `make test`, `make tidy`, `make check`, and `make dev-shell` equivalents.
- `make test` skips cleanly while no Go packages exist; errors from `go list` or package tests still fail the target.
- Shared CI also runs golangci-lint and govulncheck through `ch55secake/cheesecake-factory`; do not duplicate those workflows locally.

## GitHub Automation

- `.github/workflows/ci.yml` calls the factory's reusable Go build/test, lint, and vulnerability workflows.
- `.github/workflows/pr-labeler.yml` uses `pull_request_target` because labeling requires `pull-requests: write`; rules are in `.github/labeler.yml`.
- `.github/dependabot.yml` checks the Go module and GitHub Actions daily.
- Labeling expects feature code in `cmd/**` or `internal/**`, tests in `tests/**` or `**/*_test.go`, and documentation in `README.md` or `AGENTS.md`.
