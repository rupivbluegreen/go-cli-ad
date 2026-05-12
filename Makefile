SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

GO            ?= go
CGO_ENABLED   := 0
GOFLAGS_BUILD := -trimpath -ldflags="$(LDFLAGS)"

BIN_DIR := bin

.PHONY: help
help: ## show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ { printf "  %-22s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: ftsgw-build
ftsgw-build: ## build ftsgw-server and ftsgw-cli into bin/
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS_BUILD) -o $(BIN_DIR)/ftsgw-server ./ftsgw/cmd/ftsgw-server
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS_BUILD) -o $(BIN_DIR)/ftsgw-cli ./ftsgw/cmd/ftsgw-cli

.PHONY: ftsgw-test
ftsgw-test: ## unit tests for ftsgw
	$(GO) test -race -count=1 ./ftsgw/...

.PHONY: ftsgw-test-integration
ftsgw-test-integration: ## integration tests for ftsgw (requires Docker)
	INTEGRATION=1 $(GO) test -race -count=1 -tags=integration ./ftsgw/test/integration/...

.PHONY: ftsgw-lint
ftsgw-lint: ## run golangci-lint on ftsgw subtree
	golangci-lint run --timeout=5m ./ftsgw/...
	bash scripts/check-license-headers.sh

.PHONY: ftsgw-vet
ftsgw-vet: ## go vet ftsgw subtree
	$(GO) vet ./ftsgw/...

.PHONY: ftsgw-vendor
ftsgw-vendor: ## refresh vendor tree
	$(GO) mod tidy
	$(GO) mod vendor

.PHONY: ftsgw-image
ftsgw-image: ## build distroless container image for ftsgw-server
	docker build -f deploy/ftsgw/Dockerfile -t ftsgw-server:$(VERSION) .

.PHONY: ftsgw-sbom
ftsgw-sbom: ## emit CycloneDX SBOM
	@mkdir -p $(BIN_DIR)
	syft packages dir:./ftsgw -o cyclonedx-json > $(BIN_DIR)/ftsgw-sbom.cdx.json

.PHONY: ftsgw-sign
ftsgw-sign: ## sign image with cosign (requires COSIGN_KEY)
	cosign sign --key $${COSIGN_KEY:?must set COSIGN_KEY} ftsgw-server:$(VERSION)

.PHONY: ftsgw-clean
ftsgw-clean: ## remove ftsgw build artifacts
	rm -f $(BIN_DIR)/ftsgw-server $(BIN_DIR)/ftsgw-cli $(BIN_DIR)/ftsgw-sbom.cdx.json

.PHONY: ftsgw-demo
ftsgw-demo: ftsgw-build ## end-to-end demo against throwaway OpenLDAP
	bash scripts/ftsgw-demo.sh
