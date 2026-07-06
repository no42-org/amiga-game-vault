# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: MIT

CARGO ?= cargo
# Container image build (local). Override any of these on the command line.
CONTAINER_TOOL ?= docker
IMAGE ?= amiga-disk-vault
TAG ?= latest

.DEFAULT_GOAL := help
.PHONY: help build test run verify fmt fmt-check clippy quality clean oci

help: ## Show this help
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z_-]+:.*## /{printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the release binary
	$(CARGO) build --release

test: ## Run the test suite
	$(CARGO) test

run: ## Run the vault locally
	$(CARGO) run

fmt: ## Format the source
	$(CARGO) fmt --all

fmt-check: ## Check formatting (non-mutating, for CI)
	$(CARGO) fmt --all -- --check

clippy: ## Lint with warnings as errors
	$(CARGO) clippy --all-targets -- -D warnings

quality: fmt-check clippy ## Code-quality gate: formatting + lints

verify: build test ## Build the binary and run the full test suite
	@echo "verify: build + test suite passed"

oci: ## Build a local (host-arch) container image
	$(CONTAINER_TOOL) build -t $(IMAGE):$(TAG) .

clean: ## Remove build artifacts and the local image
	$(CARGO) clean
	-$(CONTAINER_TOOL) rmi $(IMAGE):$(TAG) 2>/dev/null || true
