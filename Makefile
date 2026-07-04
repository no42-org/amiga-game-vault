# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: MIT

CARGO ?= cargo

.PHONY: build test run verify fmt fmt-check clippy quality

build:
	$(CARGO) build --release

test:
	$(CARGO) test

run:
	$(CARGO) run

fmt:
	$(CARGO) fmt --all

# Non-mutating format check for CI.
fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

# Code-quality gate: formatting + lints.
quality: fmt-check clippy

# End-to-end verification: build the binary and run the full test suite.
verify: build test
	@echo "verify: build + test suite passed"
