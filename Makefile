.DEFAULT_GOAL := help
SHELL := /bin/bash
# The agents have to exist before the CLI is compiled: //go:embed reads the
# filesystem at build time and cannot invoke a compiler. So `build` depends on
# `agents`, and anyone who runs a bare `go build` gets a CLI that works for
# everything except installing one -- with a message saying exactly that.

GOOS_AGENT := linux
ARCHES     := amd64 arm64
AGENT_DIR  := internal/agent/bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build agents product-build clean test check help install lint unit integration artifact-check browser-install e2e vuln dev stop ui-check

all: build

# The web app `komizo ui` serves. internal/ui/dist is COMMITTED (see
# internal/ui/embed.go -- a bare `go test` and `go install module@version`
# must both work with no Node on the machine), so this is a refresh, not a
# build dependency. CI rebuilds it and diffs, which is what keeps the
# committed bytes the ones this tree produces.
ui:
	cd ui && npm ci && npm run build

# CGO_ENABLED=0 because the box is Alpine: a binary linked against glibc will
# not run there, and the failure is the kernel saying "not found" about a file
# that plainly exists.
#
# -s -w drops the symbol table and DWARF. This is embedded in the CLI twice
# over, once per architecture, so its size is the CLI's size.
agents:
	@mkdir -p $(AGENT_DIR)
	@for arch in $(ARCHES); do \
		echo "  agent  $(GOOS_AGENT)/$$arch"; \
		CGO_ENABLED=0 GOOS=$(GOOS_AGENT) GOARCH=$$arch \
			go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" \
			-o $(AGENT_DIR)/komizo-box-$(GOOS_AGENT)-$$arch ./cmd/komizo-box || exit 1; \
	done

product-build: agents
	@echo "  cli    $(VERSION)"
	@go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/komizo .


help:
	@printf '%s\n' 'make install: pinned tools, Go modules and locked UI dependencies' 'make lint / unit / integration: selectable layers' 'make test: unit + integration' 'make build: exact release archives, no publication' 'make artifact-check: checksums and archived binary identity' 'make check: all applicable checks'
install:
	mise trust .mise.toml
	mise install
	go mod download
	cd ui && npm ci --no-audit --no-fund
lint:
	bash tools/engineering/lint.sh
unit:
	go test -race -count=1 ./internal/workflows
integration: agents
	bash tools/engineering/integration.sh
test: unit integration
build: agents
	VERSION="$(VERSION)" bash tools/engineering/build-release.sh
artifact-check: build
	VERSION="$(VERSION)" bash tools/engineering/artifact-check.sh
vuln:
	govulncheck ./...
ui-check:
	bash tools/engineering/check-ui.sh
browser-install e2e dev stop:
	@echo '$@: inapplicable: operator CLI; component fixtures cover behavior without live servers'
check: lint test vuln ui-check artifact-check
clean:
	rm -rf bin dist $(AGENT_DIR)/komizo-box-*
