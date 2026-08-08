# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`soc-cli` is a Go-based command-line tool for Security Operations Center (SOC) analysts. It provides threat intelligence workflows: IP analysis, IOC extraction, URL scanning, encoding/decoding utilities, JWT decoding, and more.

## Commands

### Build

```bash
make build    # Local build to bin/soc-cli (version via `git describe`)
make run      # go run ./cmd/soc-cli (ARGS="...")
make test     # go test with race detector
make lint     # golangci-lint
make tidy     # go mod tidy && verify
make ci       # tidy + lint + test
make dist     # Cross-compile for all PLATFORMS into dist/
make release  # dist + archive (tar.gz/zip) + SHA256SUMS in dist/
make clean    # remove bin/, dist/, coverage.out
go run ./cmd/soc-cli <command>  # Run without building
```

- Version/commit/date are injected via ldflags into `internal/version` at build time; when installed via `go install` without ldflags, `internal/version`'s `init()` falls back to `runtime/debug.ReadBuildInfo()`.
- `make release` produces archives + `SHA256SUMS` in `dist/` for Windows/macOS/Linux (amd64/arm64). `release.sh vX.Y.Z` wraps this with GPG-signed checksums and a GitHub release.
- Build tooling comes from a shared `common.mk` (fetched from `go-mk`); the project `Makefile` only sets `PLATFORMS` before including it.

**No tests or linting configured.** CI runs only: `go build -v ./...`

## Architecture

The project follows a Cobra + Viper CLI pattern:

- **`cmd/soc-cli/main.go`** — calls `cmd.Execute()`. Config init (`config.InitConfig()`) happens in `cmd/root.go`'s `PersistentPreRunE`, not in `main.go`.
- **`cmd/`** — one file per command (17 commands total). Each file registers a Cobra command with flags and calls into `internal/` for logic.
- **`internal/apis/`** — one file per external API integration (IPInfo, GreyNoise, AbuseIPDB, VirusTotal, URLScan). Each makes HTTP calls via [Resty](https://github.com/go-resty/resty) and returns structured results.
- **`internal/config/`** — Viper-based config loader. On first run, creates `~/.config/soc-cli/config.yaml` with empty API key stubs and exits.
- **`internal/logic/`** — pure business logic (defang/fang URLs and emails, file hashing).
- **`internal/util/`** — shared helpers: IOC regex patterns (`regex.go`), colored table printing (`printing.go`), and misc utilities (`util.go`).
- **`internal/version/`** — version/commit/date vars, ldflags-injected at build time with a `go install` fallback via `runtime/debug.ReadBuildInfo()`.

### Configuration

User config lives at `~/.config/soc-cli/config.yaml` (Windows: `%USERPROFILE%/.config/soc-cli/config.yaml`). All five external API keys are stored there. The config is initialized automatically on first run.

**Never read or print `~/.config/soc-cli/config.yaml`.** It contains live API keys (urlscan, ipinfo, greynoise, abuseipdb, virustotal). Leaking these into conversation transcripts compromises security.

To see config schema, read `internal/config/config.go` instead.

### Adding a New Command

1. Create `cmd/<name>.go` with a `cobra.Command` and register it in its `init()` via `rootCmd.AddCommand(...)`.
2. Add API integration to `internal/apis/` if calling an external service.
3. Use `internal/util/printing.go` for consistent colored/table output.

## Key Dependencies

| Package | Purpose |
|---|---|
| `spf13/cobra` | CLI command/flag framework |
| `spf13/viper` | Config file management |
| `go-resty/resty/v3` | HTTP client for API calls |
| `fatih/color` | Terminal color output |
| `rodaine/table` | Formatted table output |
