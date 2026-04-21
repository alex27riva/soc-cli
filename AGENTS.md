# AGENTS.md

## Build Commands

```bash
make dev      # Local build to build/soc (dev-{sha} version)
make build   # Cross-platform release (via build.sh)
go run main.go <command>  # Run without building
```

- Version comes from `version.txt` (e.g., `v0.6.0`)
- Release builds to `build/soc-cli_*` for Windows/macOS/Linux

## Testing & Linting

**No tests or linting configured.** CI runs only: `go build -v ./...`

## Critical Security

**Never read or print `~/.config/soc-cli/config.yaml`.** It contains live API keys (urlscan, ipinfo, greynoise, abuseipdb, virustotal). Leaking these into conversation transcripts compromises security.

To see config schema, read `internal/config/config.go` instead.

## Release Process

```bash
./release.sh   # Builds, signs checksums (GPG), creates GitHub release
```

Requires GPG passphrase and GitHub CLI (`gh`).

## Architecture

- `cmd/*.go` — 17 Cobra commands
- `internal/apis/*.go` — External API calls (Resty HTTP client)
- `internal/config/` — Viper config loader (creates `~/.config/soc-cli/config.yaml` on first run)
- `internal/logic/` — Business logic (defang/fang, hashing)
- `internal/util/` — Shared helpers (regex, colored printing)

## Commands

| Command | Description |
|---|---|
| `ip <addr>` | Threat intel via IPInfo / GreyNoise / AbuseIPDB |
| `extract-ioc <file>` | Extract IPs, URLs, hashes, emails |
| `url-scan <url>` | Submit to urlscan.io |
| `file-check <file>` | VirusTotal lookup/upload |
| `email <file.eml>` | Parse .eml for attachments, links, SPF/DKIM/DMARC |
| `hash <file>` | MD5/SHA1/SHA256/Blake3 |
| `defang/fang` | Safe IOC format conversion |
| `decode jwt` | JWT decode with `--expired` flag |

## Setup

First run creates `~/.config/soc-cli/config.yaml` with empty API key stubs.

```bash
soc-cli config set ipinfo
soc-cli config set greynoise
soc-cli config set abuseipdb
soc-cli config set urlscan
soc-cli config set virustotal
```

## Adding a Command

1. Create `cmd/<name>.go` with a Cobra command
2. Register in `init()` via `rootCmd.AddCommand(...)`
3. Add API logic to `internal/apis/` if needed
4. Use `internal/util/printing.go` for consistent table output