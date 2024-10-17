#!/usr/bin/env bash

export VERSION=dev-$(git rev-parse --short HEAD)
go build -o soc -ldflags "-X 'soc-cli/cmd.Version=$VERSION'"