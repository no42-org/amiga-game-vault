# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: MIT

CARGO ?= cargo

.PHONY: build test run verify fmt clippy

build:
	$(CARGO) build --release

test:
	$(CARGO) test

run:
	$(CARGO) run

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

# End-to-end verification: build the binary and run the full test suite.
verify: build test
	@echo "verify: build + test suite passed"
