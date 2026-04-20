BINARY   := soc-cli
BUILD_DIR := build
VERSION  := $(shell cat version.txt 2>/dev/null | tr -d '[:space:]')
COMMIT   := $(shell git rev-parse --short HEAD)
DATE     := $(shell date '+%Y%m%d')
LDFLAGS  := -X 'soc-cli/cmd.Version=$(VERSION)' -X 'soc-cli/cmd.Commit=$(COMMIT)' -X 'soc-cli/cmd.Date=$(DATE)'

.PHONY: all build dev clean help

all: build

## build: cross-platform release build via build.sh
build:
	./build.sh

## dev: quick local build -> build/soc
dev:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-X 'soc-cli/cmd.Version=dev-$(COMMIT)' -X 'soc-cli/cmd.Commit=$(COMMIT)' -X 'soc-cli/cmd.Date=$(DATE)'" -o $(BUILD_DIR)/soc .

## clean: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'
