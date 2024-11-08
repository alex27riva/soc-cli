#!/usr/bin/env bash

program_name="soc-cli"

# Determine the version
if [ -n "$1" ]; then
    version=$1
else
    # Get the short SHA of the current commit
    short_sha=$(git rev-parse --short HEAD)
    echo "No version specified, defaulting to dev-${short-sha}"
    version="dev-${short_sha}"
fi

# Remove existing soc-cli_* files if they exist
echo ":: Removing existing ${program_name} files..."
rm build/${program_name}_*

# Build for Windows (64-bit)
echo ":: Building for Windows (64-bit)..."
GOOS=windows GOARCH=amd64 go build -ldflags "-X 'soc-cli/cmd.Version=${version}'" -o "build/${program_name}_${version}_windows_amd64.exe"
if [ $? -ne 0 ]; then
    echo "Failed to build for Windows."
    exit 1
fi

# Build for macOS (Intel)
echo ":: Building for macOS (Intel)..."
GOOS=darwin GOARCH=amd64 go build -ldflags "-X 'soc-cli/cmd.Version=${version}'" -o "build/${program_name}_${version}_darwin_amd64"
if [ $? -ne 0 ]; then
    echo "Failed to build for macOS (Intel)."
    exit 1
fi

# Build for macOS (Apple Silicon)
echo ":: Building for macOS (Apple Silicon)..."
GOARCH=arm64 go build -ldflags "-X 'soc-cli/cmd.Version=${version}'" -o "build/${program_name}_${version}_darwin_arm64"
if [ $? -ne 0 ]; then
    echo "Failed to build for macOS (Apple Silicon)."
    exit 1
fi

# Build for Linux (64-bit)
echo ":: Building for Linux (64-bit)..."
GOOS=linux GOARCH=amd64 go build -ldflags "-X 'soc-cli/cmd.Version=${version}'" -o "build/${program_name}_${version}_linux_amd64"
if [ $? -ne 0 ]; then
    echo "Failed to build for Linux (64-bit)."
    exit 1
fi

echo "Build completed successfully!"