# Project Variables
BINARY_NAME=gocontainer
GO_VERSION=1.26.10
DOCKER_IMAGE=alpine:latest
ROOTFS_DIR=./cache/alpine_rootfs

# Go Commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Targets
.PHONY: all build clean test run pull help

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@$(GOBUILD) -o $(BINARY_NAME) .

clean:
	@echo "Cleaning up..."
	@$(GOCLEAN)
	@rm -f $(BINARY_NAME)
	@rm -rf ./cache

test:
	@echo "Running tests..."
	@$(GOTEST) -v ./...

pull:
	@echo "Pulling Alpine rootfs..."
	@./$(BINARY_NAME) pull

run: build
	@echo "Running container (requires root)..."
	@sudo ./$(BINARY_NAME) run /bin/sh

help:
	@echo "Usage:"
	@echo "  make build    - Build the binary"
	@echo "  make clean    - Remove binary and cache"
	@echo "  make test     - Run tests"
	@echo "  make pull     - Download Alpine rootfs"
	@echo "  make run      - Run container with /bin/sh (sudo required)"
	@echo "  make help     - Show this help message"
