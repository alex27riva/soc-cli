# soc-cli

`soc-cli` is a command-line tool designed for SOC analysts (Security Operations Center) to aid in IP analysis, IOC extraction, URL scanning, and more.
Built with Go, this tool provides a variety of commands to simplify threat intelligence workflows.

## Features

- **IP Analysis**: Lookup IP addresses for threat intelligence, geo-location, ASN info via IPInfo, GreyNoise, and AbuseIPDB.
- **IOC Extraction**: Extract indicators of compromise such as URLs, IP addresses, email addresses, and file hashes from text files.
- **URL Scanning**: Submit URLs to urlscan.io and retrieve threat verdict.
- **File Check**: Check a file against VirusTotal by hash; upload it for scanning if not found.
- **Email Analysis**: Analyze `.eml` files for attachments, links, and email authentication (SPF, DKIM, DMARC).
- **Hash Calculation**: Calculate MD5, SHA1, and SHA256 hashes of files.
- **JWT Decode**: Decode JWT tokens and optionally check expiration.
- **Encode / Decode**: Base64 encode and decode strings.
- **Defang / Fang**: Defang or re-fang URLs and email addresses for safe sharing in reports.
- **Strings**: Extract printable strings from a file.

## Quick Start

```bash
go install github.com/alex27riva/soc-cli@latest
```

Requires Go 1.18+. The binary will be placed in `$GOPATH/bin` (make sure it's in your `$PATH`).

## Installation

### From source

1. **Clone the repository**:

    ```bash
    git clone https://github.com/alex27riva/soc-cli.git
    cd soc-cli
    ```

2. **Build the project**:

    ```bash
    go build -o soc-cli
    ```

3. **Run the tool**:

    ```bash
    ./soc-cli
    ```

## Configuration

Use the `config set` command to configure API keys for the services you need:

```bash
soc-cli config set ipinfo <api-key>
soc-cli config set greynoise <api-key>
soc-cli config set abuseipdb <api-key>
soc-cli config set urlscan <api-key>
soc-cli config set virustotal <api-key>
```

To view configured keys: `soc-cli config list`

Config is stored at `~/.config/soc-cli/config.yaml` (Windows: `%USERPROFILE%/.config/soc-cli/config.yaml`).

## Usage

The basic usage syntax is:

```bash
soc-cli [command] [options]
```

### Commands

`ip`

Analyze an IP address for threat intelligence, geolocation, AS information, and IP type.

```bash
soc-cli ip <IPv4_address>
```

`extract-ioc`

Extract IOCs from a text file.

```bash
soc-cli extract-ioc <file_path>
```

`url-scan`

Submit a URL for scanning and analysis.

```bash
soc-cli url-scan <URL>
```

`defang` and `fang`

Defang or re-fang URLs and email addresses for safe sharing.

```bash
soc-cli defang <URL_or_email>
soc-cli fang <URL_or_email>
```

`email`

Analyze an `.eml` file for attachments, links, and authentication results (SPF, DKIM, DMARC).

```bash
soc-cli email <file.eml>
```

`file-check`

Calculate the SHA256 of a file and look it up on VirusTotal. If not found, prompts to upload it for scanning.

```bash
soc-cli file-check <file_path>
```

`hash`

Calculate MD5, SHA1, and SHA256 hashes of a file.

```bash
soc-cli hash <file_path>
soc-cli hash --json <file_path>
```

`strings`

Extract printable strings from a binary or any file.

```bash
soc-cli strings <file_path>
soc-cli strings --min-length 8 <file_path>
```

`encode base64` / `decode base64`

Encode or decode a Base64 string.

```bash
soc-cli encode base64 <string>
soc-cli decode base64 <base64-string>
```

`decode jwt`

Decode a JWT token and print its header, payload, and claims. Use `--expired` to exit with code 1 if the token is expired.

```bash
soc-cli decode jwt <token>
soc-cli decode jwt --expired <token>
```

`misc myip`

Print your current public IP address.

```bash
soc-cli misc myip
```

`version`

Show the current version of `soc-cli`.

```bash
soc-cli version
```

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

# Encode/decode Base64
soc-cli encode base64 "hello world"
soc-cli decode base64 "aGVsbG8gd29ybGQ="

# Defang a URL for safe sharing
soc-cli defang https://malicious.example.com

# Get your public IP
soc-cli misc myip
```

## Contributing

We welcome contributions! To get started:

1. Fork the repository
2. Create a new branch (git checkout -b feature/YourFeature)
3. Make your changes
4. Commit your changes (git commit -am 'Add YourFeature')
5. Push to the branch (git push origin feature/YourFeature)
6. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
