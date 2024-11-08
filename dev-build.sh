#!/usr/bin/env bash

VERSION=dev-$(git rev-parse --short HEAD)
go build -o build/soc -ldflags "-X 'soc-cli/cmd.Version=$VERSION'"