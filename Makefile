SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: help build build-release sign

BLUE := $(shell printf '\033[0;34m')
GREEN := $(shell printf '\033[0;32m')
YELLOW := $(shell printf '\033[1;33m')
NC := $(shell printf '\033[0m')

# Stable identifier codesigned into the binary so its macOS Keychain code
# requirement stays the same across rebuilds. An unsigned or ad-hoc binary's
# requirement is pinned to its content hash, so "Always Allow" never sticks.
# The first available codesigning identity is used; on a machine with more
# than one, sign warns which one it picked. Override with
# `make build SIGN_IDENTITY="Developer ID Application: ..."`.
BUNDLE_ID ?= com.affinidi.fabric-cli
CODESIGN_IDENTITY_COUNT := $(shell security find-identity -v -p codesigning 2>/dev/null | grep -c '".*"')
SIGN_IDENTITY ?= $(shell security find-identity -v -p codesigning 2>/dev/null | grep -m1 -oE '"[^"]+"' | tr -d '"')
BIN ?= target/debug/fabric

.DEFAULT_GOAL := help

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ { printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the CLI (debug) and codesign it on macOS
	@echo "$(BLUE)📦 Building fabric (debug)...$(NC)"
	@cargo build
	@$(MAKE) --no-print-directory sign BIN=target/debug/fabric

build-release: ## Build the CLI (release) and codesign it on macOS
	@echo "$(BLUE)📦 Building fabric (release)...$(NC)"
	@cargo build --release
	@$(MAKE) --no-print-directory sign BIN=target/release/fabric

sign: ## Codesign a built binary (BIN=path) so macOS Keychain trust survives rebuilds
	@if [ "$$(uname)" != "Darwin" ]; then \
		echo "$(YELLOW)⚠️  Not macOS, skipping codesign$(NC)"; \
	elif [ -z "$(SIGN_IDENTITY)" ]; then \
		echo "$(YELLOW)⚠️  No codesigning identity found (security find-identity -v -p codesigning), skipping$(NC)"; \
	else \
		if [ "$(CODESIGN_IDENTITY_COUNT)" -gt 1 ] 2>/dev/null; then \
			echo "$(YELLOW)⚠️  Multiple codesigning identities found, using \"$(SIGN_IDENTITY)\" (override with SIGN_IDENTITY=\"...\" if wrong)$(NC)"; \
		fi; \
		codesign --force --options runtime --sign "$(SIGN_IDENTITY)" --identifier "$(BUNDLE_ID)" "$(BIN)"; \
		echo "$(GREEN)✅ Signed $(BIN) with $(SIGN_IDENTITY)$(NC)"; \
	fi
