.PHONY: help build test test-integration test-unit clean install run run-tls run-mtls fmt vet lint coverage

# Default target
.DEFAULT_GOAL := help

# Binary name
BINARY_NAME := echo-server

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOINSTALL := $(GOCMD) install
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet
GOCLEAN := $(GOCMD) clean

# Build flags
BUILD_FLAGS := -v

# Test flags
TEST_FLAGS := -v -race
COVERAGE_FLAGS := -coverprofile=coverage.txt -covermode=atomic

help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

build: ## Build the echo-server binary
	$(GOBUILD) $(BUILD_FLAGS) -o $(BINARY_NAME)

install: ## Install echo-server to GOPATH/bin
	GO111MODULE=on $(GOINSTALL) github.com/igor-kupczynski/http2-utils/echo-server@latest

test: test-unit test-integration ## Run all tests (unit + integration)

test-unit: ## Run unit tests only
	$(GOTEST) $(TEST_FLAGS) -run '^Test[^I]' .

test-integration: ## Run integration tests only
	$(GOTEST) $(TEST_FLAGS) -run '^TestIntegration' .

coverage: ## Generate test coverage report
	$(GOTEST) $(COVERAGE_FLAGS) .
	$(GOCMD) tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated: coverage.html"

fmt: ## Format Go code
	$(GOFMT) ./...

vet: ## Run go vet
	$(GOVET) ./...

lint: fmt vet ## Run formatters and linters

clean: ## Remove build artifacts and test files
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.txt coverage.html
	rm -f *.pem *.key

run: build ## Build and run echo-server in plain HTTP mode
	./$(BINARY_NAME) -addr :8080

run-tls: build ## Build and run echo-server in TLS mode (requires certs in /tmp)
	@if [ ! -f /tmp/domain.pem ] || [ ! -f /tmp/domain.key ]; then \
		echo "Error: TLS certificates not found in /tmp/"; \
		echo "Run: cd /tmp && selfsigned-gen -domains 'localhost,127.0.0.1'"; \
		exit 1; \
	fi
	./$(BINARY_NAME) -addr :8443 -tlsCert /tmp/domain.pem -tlsKey /tmp/domain.key

run-mtls: build ## Build and run echo-server in mTLS mode (requires certs in /tmp)
	@if [ ! -f /tmp/domain.pem ] || [ ! -f /tmp/domain.key ] || [ ! -f /tmp/ca.pem ]; then \
		echo "Error: TLS certificates not found in /tmp/"; \
		echo "Run: cd /tmp && selfsigned-gen -domains 'localhost,127.0.0.1'"; \
		exit 1; \
	fi
	./$(BINARY_NAME) -addr :8443 -healthCheck :8444 \
		-tlsCert /tmp/domain.pem -tlsKey /tmp/domain.key \
		-mtlsMode require_and_verify -clientCAs /tmp/ca.pem

# Development helpers
.PHONY: dev-setup dev-certs dev-test

dev-setup: ## Set up development environment
	@echo "Installing dependencies..."
	$(GOGET) -v -t -d ./...
	@echo "Development environment ready"

dev-certs: ## Generate test certificates in /tmp
	@echo "Generating test certificates..."
	cd /tmp && selfsigned-gen -domains "localhost,127.0.0.1"
	@echo "Certificates generated in /tmp/"
	@ls -la /tmp/*.pem /tmp/*.key

dev-test: build dev-certs ## Quick development test cycle
	@echo "Starting server in background..."
	./$(BINARY_NAME) -addr :8080 > /tmp/echo-server.log 2>&1 & echo $$! > /tmp/echo-server.pid
	@sleep 1
	@echo "Testing plain HTTP..."
	@curl -s http://localhost:8080/test || true
	@echo "\nStopping server..."
	@kill `cat /tmp/echo-server.pid` 2>/dev/null || true
	@rm -f /tmp/echo-server.pid /tmp/echo-server.log
	@echo "Development test complete"
