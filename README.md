# soc-cli

<p align="center">
  <img src="assets/mascotte.jpg" alt="soc-cli mascot" width="200"/>
</p>

`soc-cli` is a command-line tool for SOC analysts to aid in IP analysis, IOC extraction, URL scanning, and more.
Built with Go, it provides commands to simplify threat intelligence workflows.

![Made with VHS](https://vhs.charm.sh/vhs-6AzRS1H0zIfYq7vWe5lBjj.gif)

## Features

- **IP Analysis**: Lookup IP addresses for threat intelligence, geo-location, and ASN info via IPInfo, GreyNoise, and AbuseIPDB
- **IOC Extraction**: Extract indicators of compromise (URLs, IPs, emails, file hashes) from text files
- **URL Scanning**: Submit URLs to urlscan.io and retrieve threat verdict
- **File Check**: Check a file against VirusTotal by hash; upload for scanning if not found
- **Email Analysis**: Analyze `.eml` files for attachments, links, and authentication (SPF, DKIM, DMARC)
- **Hash Calculation**: MD5, SHA1, SHA256, and Blake3 — computed in parallel
- **JWT Decode**: Decode JWT tokens and optionally check expiration
- **Encode / Decode**: Base64 encode and decode
- **Defang / Fang**: Convert IOCs to safe sharing format and back
- **Strings**: Extract printable strings from any file

## Installation

Requires Go 1.18+.

```bash
go install github.com/alex27riva/soc-cli@latest
```

Add a short alias (add to `~/.bashrc` or `~/.zshrc` to persist):

```bash
alias soc='soc-cli'
```

**Or build from source:**

```bash
git clone https://github.com/alex27riva/soc-cli.git
cd soc-cli && go build -o soc-cli
```

## Configuration

Set API keys interactively (not echoed, won't appear in shell history):

```bash
soc-cli config set ipinfo
soc-cli config set greynoise
soc-cli config set abuseipdb
soc-cli config set urlscan
soc-cli config set virustotal
```

To view configured keys: `soc-cli config list`

Config is stored at `~/.config/soc-cli/config.yaml` (Windows: `%USERPROFILE%/.config/soc-cli/config.yaml`).

## Commands

| Command | Description |
|---|---|
| `ip <addr>` | Threat intel, geo, ASN via IPInfo / GreyNoise / AbuseIPDB |
| `extract-ioc <file>` | Extract IPs, URLs, hashes, emails from text |
| `url-scan <url>` | Submit URL to urlscan.io |
| `file-check <file>` | SHA256 lookup + upload to VirusTotal |
| `email <file.eml>` | Parse attachments, links, SPF/DKIM/DMARC |
| `hash <file>` | MD5 / SHA1 / SHA256 / Blake3 (parallel) |
| `strings <file>` | Extract printable strings |
| `defang` / `fang` | Safe IOC sharing format |
| `encode/decode base64` | Base64 encode/decode |
| `decode jwt` | Decode JWT; `--expired` exits 1 if token is expired |
| `misc myip` | Print your public IP |

## Examples

```bash
# Analyze an IP address
soc-cli ip 8.8.8.8

# Extract IOCs from a log file
soc-cli extract-ioc logs.txt

# Submit a URL for threat intelligence
soc-cli url-scan https://example.com

# Check a file against VirusTotal
soc-cli file-check /path/to/malware.exe

# Analyze an email file
soc-cli email phishing.eml

# Calculate file hashes
soc-cli hash /path/to/file.txt

# Decode a JWT token
soc-cli decode jwt eyJhbGci...

# Defang a URL for safe sharing
soc-cli defang https://malicious.example.com
```

## Contributing

PRs welcome. Open an issue first for large changes.

## License

MIT — see [LICENSE](LICENSE).
