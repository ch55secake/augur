# Agent Instructions

## Project

- This is the Go module `github.com/ch55secake/augur`, targeting Go `1.26.5`.
- The intended program is a launchd service that watches active SSH connections and terminates unrecognized ones.
- There are currently no Go packages, Makefile, or other task runner; commands run from the repository root.

## Verification

- Run `go mod tidy` after changing module dependencies.
- Run `go build ./...` for build verification and `go test ./...` for tests; these are the shared CI commands.
- Shared CI also runs golangci-lint and govulncheck through `ch55secake/cheesecake-factory`; do not duplicate those workflows locally.

## GitHub Automation

- `.github/workflows/ci.yml` calls the factory's reusable Go build/test, lint, and vulnerability workflows.
- `.github/workflows/pr-labeler.yml` uses `pull_request_target` because labeling requires `pull-requests: write`; rules are in `.github/labeler.yml`.
- `.github/dependabot.yml` checks the Go module and GitHub Actions daily.
- Labeling expects feature code in `cmd/**` or `internal/**`, tests in `tests/**` or `**/*_test.go`, and documentation in `README.md` or `AGENTS.md`.
