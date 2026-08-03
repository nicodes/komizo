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

# What CI runs, and what to run before pushing.
#
# shellcheck FIRST, and through docker when it is not installed. The Go test
# that runs it skips itself when the tool is absent, and a skip is a green tick
# -- which is exactly how `A && B || C` reached CI: `make check` passed locally
# and the gate had not run at all.
check: agents
	@command -v shellcheck >/dev/null 2>&1 \
		&& shellcheck -s sh scripts/*.sh \
		|| docker run --rm -v "$(CURDIR)/scripts:/mnt:ro" -w /mnt \
			koalaman/shellcheck:stable -s sh $(notdir $(wildcard scripts/*.sh))
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	go test ./...
	GOOS=darwin go build ./...

clean:
	rm -rf bin $(AGENT_DIR)/komizo-box-*
