# The agents have to exist before the CLI is compiled: //go:embed reads the
# filesystem at build time and cannot invoke a compiler. So `build` depends on
# `agents`, and anyone who runs a bare `go build` gets a CLI that works for
# everything except installing one -- with a message saying exactly that.

GOOS_AGENT := linux
ARCHES     := amd64 arm64
AGENT_DIR  := internal/agent/bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build agents clean test check

all: build

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

build: agents
	@echo "  cli    $(VERSION)"
	@go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/komizo .

test:
	go test ./...

# SHELLCHECK_VERSION is read out of .mise.toml rather than written here.
#
# One number, in the file that installs the tool. Two copies would drift, and
# the drift is silent -- which is the whole of komizo#59's second half.
SHELLCHECK_VERSION := $(shell sed -n 's/^shellcheck *= *"\(.*\)"$$/\1/p' .mise.toml)

# What CI runs, and what to run before pushing.
#
# shellcheck FIRST, and through docker when the pinned one is not installed. The
# Go tests that run it skip themselves when the tool is absent, and a skip is a
# green tick -- which is exactly how `A && B || C` reached CI: `make check`
# passed locally and the gate had not run at all.
#
# THE VERSION IS CHECKED, not just the presence. This used to be
#
#	command -v shellcheck && shellcheck ... || docker run ...
#
# which is two failures in one line. A local shellcheck of ANY version was
# accepted, so 0.9.0 and 0.11.0 both counted as "the check"; and because `||`
# reads a non-zero exit as "the first branch was unavailable", a local shellcheck
# that FOUND SOMETHING fell through to the docker run and could be overruled by
# it. A lint that reports a problem is not a lint that failed to run.
#
# So: one `if`, whose exit status is the step's, and a version comparison rather
# than a `command -v`.
check: agents
	@test -n "$(SHELLCHECK_VERSION)" || { \
		echo "no shellcheck pin in .mise.toml -- the lint has no version to be"; exit 1; }
	@if shellcheck --version 2>/dev/null | grep -qx 'version: $(SHELLCHECK_VERSION)'; then \
		echo "  lint   shellcheck $(SHELLCHECK_VERSION)"; \
		shellcheck -s sh scripts/*.sh; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "  lint   shellcheck $(SHELLCHECK_VERSION) (docker)"; \
		docker run --rm -v "$(CURDIR)/scripts:/mnt:ro" -w /mnt \
			koalaman/shellcheck:v$(SHELLCHECK_VERSION) -s sh $(notdir $(wildcard scripts/*.sh)); \
	else \
		echo "shellcheck $(SHELLCHECK_VERSION) is not installed and docker is not either."; \
		echo "\`mise install\` gets it. Running the Go suite without it would SKIP"; \
		echo "the six checks over the shell that runs as root on a box."; \
		exit 1; \
	fi
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	go test ./...
	GOOS=darwin go build ./...

clean:
	rm -rf bin $(AGENT_DIR)/komizo-box-*
