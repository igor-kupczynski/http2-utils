.PHONY: help build test test-integration test-unit clean install run run-tls run-mtls fmt vet lint coverage docker-build docker-push docker-run docker-clean

# Default target
.DEFAULT_GOAL := help

# Binary name
BINARY_NAME := echo-server

# Docker parameters
DOCKER_REGISTRY ?= docker.io
DOCKER_IMAGE_NAME ?= $(DOCKER_REGISTRY)/$(shell whoami)/echo-server
GIT_SHA := $(shell git rev-parse --short HEAD)
DOCKER_TAG ?= $(GIT_SHA)
DOCKER_IMAGE := $(DOCKER_IMAGE_NAME):$(DOCKER_TAG)
DOCKER_IMAGE_LATEST := $(DOCKER_IMAGE_NAME):latest

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
	$(GOTEST) $(TEST_FLAGS) ./...

test-integration: ## Run integration tests only
	$(GOTEST) $(TEST_FLAGS) -tags integration ./...

coverage: ## Generate test coverage report
	$(GOTEST) -coverprofile=unit.cover -covermode=atomic ./...
	$(GOCMD) tool cover -func=unit.cover
	$(GOTEST) -tags integration -coverprofile=integration.cover -covermode=atomic ./...
	$(GOCMD) tool cover -func=integration.cover
	@echo "Coverage summaries generated: unit.cover integration.cover"

fmt: ## Format Go code
	$(GOFMT) ./...

vet: ## Run go vet
	$(GOVET) ./...

lint: fmt vet ## Run formatters and linters

clean: ## Remove build artifacts and test files
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.txt coverage.html unit.cover integration.cover
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

# Docker targets
.PHONY: docker-build docker-push docker-run docker-clean docker-info

docker-info: ## Display Docker image information
	@echo "Docker Image Configuration:"
	@echo "  Registry:     $(DOCKER_REGISTRY)"
	@echo "  Image Name:   $(DOCKER_IMAGE_NAME)"
	@echo "  Git SHA:      $(GIT_SHA)"
	@echo "  Tag:          $(DOCKER_TAG)"
	@echo "  Full Image:   $(DOCKER_IMAGE)"
	@echo "  Latest Tag:   $(DOCKER_IMAGE_LATEST)"
	@echo ""
	@echo "Override with:"
	@echo "  make docker-build DOCKER_REGISTRY=ghcr.io DOCKER_IMAGE_NAME=ghcr.io/myuser/echo-server"

docker-build: ## Build Docker image tagged with git SHA
	@echo "Building Docker image: $(DOCKER_IMAGE)"
	docker build -t $(DOCKER_IMAGE) -t $(DOCKER_IMAGE_LATEST) .
	@echo "Successfully built: $(DOCKER_IMAGE)"
	@echo "Also tagged as:     $(DOCKER_IMAGE_LATEST)"

docker-push: docker-build ## Build and push Docker image to registry
	@echo "Pushing Docker image: $(DOCKER_IMAGE)"
	docker push $(DOCKER_IMAGE)
	@echo "Pushing Docker image: $(DOCKER_IMAGE_LATEST)"
	docker push $(DOCKER_IMAGE_LATEST)
	@echo "Successfully pushed both tags"

docker-run: docker-build ## Build and run Docker container in plain HTTP mode
	@echo "Running Docker container: $(DOCKER_IMAGE)"
	docker run --rm -p 8080:8080 $(DOCKER_IMAGE)

docker-run-tls: docker-build dev-certs ## Build and run Docker container in TLS mode
	@echo "Running Docker container with TLS: $(DOCKER_IMAGE)"
	docker run --rm -p 8443:8443 \
		-v /tmp/domain.pem:/certs/domain.pem:ro \
		-v /tmp/domain.key:/certs/domain.key:ro \
		$(DOCKER_IMAGE) \
		-addr :8443 \
		-tlsCert /certs/domain.pem \
		-tlsKey /certs/domain.key

docker-clean: ## Remove locally built Docker images
	@echo "Removing Docker images..."
	docker rmi $(DOCKER_IMAGE) $(DOCKER_IMAGE_LATEST) 2>/dev/null || true
	@echo "Docker images removed"
