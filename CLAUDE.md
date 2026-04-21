# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`soc-cli` is a Go-based command-line tool for Security Operations Center (SOC) analysts. It provides threat intelligence workflows: IP analysis, IOC extraction, URL scanning, encoding/decoding utilities, JWT decoding, and more.

## Commands

### Build

```bash
make dev      # Local build to build/soc (dev-{sha} version)
make build   # Cross-platform release (via build.sh)
go run main.go <command>  # Run without building
```

- Version comes from `version.txt` (e.g., `v0.6.0`)
- Release builds to `build/soc-cli_*` for Windows/macOS/Linux

**No tests or linting configured.** CI runs only: `go build -v ./...`

## Architecture

The project follows a Cobra + Viper CLI pattern:

- **`main.go`** — calls `config.InitConfig()` then `cmd.Execute()`
- **`cmd/`** — one file per command (17 commands total). Each file registers a Cobra command with flags and calls into `internal/` for logic.
- **`internal/apis/`** — one file per external API integration (IPInfo, GreyNoise, AbuseIPDB, VirusTotal, URLScan). Each makes HTTP calls via [Resty](https://github.com/go-resty/resty) and returns structured results.
- **`internal/config/`** — Viper-based config loader. On first run, creates `~/.config/soc-cli/config.yaml` with empty API key stubs and exits.
- **`internal/logic/`** — pure business logic (defang/fang URLs and emails, file hashing).
- **`internal/util/`** — shared helpers: IOC regex patterns (`regex.go`), colored table printing (`printing.go`), and misc utilities (`util.go`).

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
