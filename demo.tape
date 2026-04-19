Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 450
Set Theme "Dracula"
Set Padding 10
Set Margin 10
Set MarginFill "#282a36"
Set Framerate 30
Set PlaybackSpeed 1

# Install from Go
Type "go install github.com/alex27riva/soc-cli@latest"
Enter
Sleep 2s

# Set alias
Type "alias soc='soc-cli'"
Enter
Sleep 300ms

# --- Splash screen ---
Type "soc | head -n 9"
Sleep 300ms
Enter
Sleep 2s
Ctrl+L
Sleep 300ms

# --- Defang a malicious URL ---
Type "# Defang a malicious URL before sharing in a report"
Sleep 300ms
Enter
Sleep 300ms
Type "soc defang 'https://malware-download.xyz/payload.exe'"
Sleep 300ms
Enter
Sleep 1.5s

# --- Fang it back ---
Type "# Fang it back to restore the original URL"
Sleep 300ms
Enter
Sleep 300ms
Type "soc fang 'hxxps://malware-download[.]xyz/payload.exe'"
Sleep 300ms
Enter
Sleep 1.5s
Ctrl+L
Sleep 300ms

# --- Extract IOCs from a file ---
Type "# Extract all IOCs from an incident report"
Sleep 300ms
Enter
Sleep 300ms
Type "soc extract-ioc demo/sample_iocs.txt"
Sleep 300ms
Enter
Sleep 2s
Ctrl+L
Sleep 300ms

# --- Hash a file ---
Type "# Hash a suspicious file"
Sleep 300ms
Enter
Sleep 300ms
Type "soc hash demo/sample_iocs.txt"
Sleep 300ms
Enter
Sleep 2s
Ctrl+L
Sleep 300ms

# --- Base64 encode ---
Type "# Base64 encode a string"
Sleep 300ms
Enter
Sleep 300ms
Type "soc encode base64 'suspicious_payload_string'"
Sleep 300ms
Enter
Sleep 1.5s

# --- Base64 decode ---
Type "# Decode a suspicious base64 blob"
Sleep 300ms
Enter
Sleep 300ms
Type "soc decode base64 'c3VzcGljaW91c19wYXlsb2FkX3N0cmluZw=='"
Sleep 300ms
Enter
Sleep 1.5s
Ctrl+L
Sleep 300ms

# --- Pipe example ---
Type "# Commands can be chained via pipes"
Sleep 300ms
Enter
Sleep 300ms
Type "echo 'malware-string' | soc encode base64 | soc decode base64"
Sleep 300ms
Enter
Sleep 1.5s
Ctrl+L
Sleep 300ms

# --- URL decode ---
Type "# URL decode an encoded IOC"
Sleep 300ms
Enter
Sleep 300ms
Type "soc decode url 'hxxps%3A%2F%2Fc2.badactor.net%2Fcheck-in'"
Sleep 300ms
Enter
Sleep 1.5s

# --- JWT decode ---
Type "# Decode a JWT from a suspicious request"
Sleep 300ms
Enter
Sleep 300ms
Set TypingSpeed 10ms
Type `soc decode jwt 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'`
Set TypingSpeed 50ms
Sleep 300ms
Enter
Sleep 2s

Sleep 1s
