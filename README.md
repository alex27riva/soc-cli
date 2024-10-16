# soc-cli

`soc-cli` is a command-line tool designed for Security Operations Center (SoC) analysts to aid in IP analysis, IOC extraction, URL scanning, and more.
Built with Go, this tool provides a variety of commands to simplify threat intelligence workflows.

## Features

- **IP Analysis**: Lookup IP addresses for threat intelligence, geo-location, AS info, and IP type.
- **IOC Extraction**: Extract indicators of compromise such as URLs, IP addresses, email addresses, and file hashes from text files.
- **URL Analysis**: Submit URLs for scanning and obtain threat intelligence.
- **Hash Calculation**: Calculate SHA256 hashes of files for integrity checks.
- **Email Analysis**: Analyze `.eml` files for attachments, links, and email authentication (SPF, DKIM, DMARC).
- **Defang/Fang**: Defang or re-fang URLs and email addresses to safely share them in reports.

## Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/yourusername/soc-cli.git
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

<!-- Alternatively, you can download a pre-built binary from the [releases](https://github.com/yourusername/soc-cli/releases) page. -->

## Configuration

The tool reads API keys and other configuration settings from a config file located in `~/.config/soc-cli/config.yaml`.
On Windows the path is `%USERPROFILE%/.config/soc-cli/config.yaml`

Example structure:

```yaml
api_keys:
  urlscan:
    api_key: your-urlscan-api-key

  ipinfo:
    api_key: your-ipinfo-api-key

```

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

`urlscan`

Submit a URL for scanning and analysis.

```bash
soc-cli urlscan <URL>
```

`defang` and `fang`

Defang or re-fang URLs and email addresses for safe sharing.

```bash
soc-cli defang <URL_or_email>
soc-cli fang <URL_or_email>
```

`hash`

Calculate the hash of a file.

```bash
soc-cli hash <file_path>
```

`version`

Show the current version of `soc-cli` tool.

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
soc-cli urlscan https://example.com

# Calculate the SHA256 hash of a file
soc-cli hash /path/to/file.txt

# Defang an email address for safe sharing
soc-cli defang user@example.com

# Show the current version
soc-cli version
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
