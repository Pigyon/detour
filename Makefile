# Variables
BINARY_NAME=detour
GO=go
GOFLAGS=-v

# Build variables
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-X github.com/nedlir/detour/internal/cli.version=$(VERSION) -X github.com/nedlir/detour/internal/cli.commit=$(COMMIT) -X github.com/nedlir/detour/internal/cli.date=$(DATE)"

.PHONY: all build clean test lint run install help lab-gate

all: clean lint test build

## build: Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/detour

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html

## test: Run all tests
test:
	@echo "Running tests..."
	$(GO) test -race -shuffle=on -coverprofile=coverage.out ./...

## lab-gate: Run the lab zero-FP and recall tests
lab-gate:
	$(GO) test -race -count=1 ./internal/attack -run 'TestLab(ZeroFalsePositives|Recall)$$'
	$(GO) test -race -count=1 ./internal/js -run 'TestCollectPage(AgainstLab|LabClientSideFixtures)$$'

## lint: Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...

## lint-fix: Run linter and auto-fix issues
lint-fix:
	golangci-lint run --fix ./...

## fmt: Format code
fmt:
	gofumpt -l -w .
	goimports -w .

## run: Build and run the application
run: build
	./bin/$(BINARY_NAME)

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
