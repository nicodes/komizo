// Package agent carries the compiled komizo-box binaries, so that installing
// one is something `komizo init` can do over a plain SSH connection.
//
// EMBEDDED rather than downloaded. init already works on a box with nothing on
// it but sshd, and making it fetch a release URL would add a network dependency
// and a supply-chain step to the one operation that is supposed to work when
// very little else does. It is also the pattern komizo already uses for the
// provisioning shell -- see scripts/embed.go -- for the same reason.
//
// The cost is the CLI's size, and one build-order constraint: the binaries have
// to EXIST before the CLI is compiled, because //go:embed reads the filesystem
// at build time and cannot invoke a compiler. `make agents` builds them; the
// release workflow runs it. A CLI built without that step still compiles and
// still does everything else -- the failure is one clear message at the moment
// somebody tries to install an agent, rather than a build nobody can run.
package agent

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
)

// bin holds one binary per architecture, built by `make agents`.
//
// all: so the directory embeds even when it holds nothing but the .keep that
// keeps it in git. Without that this would not compile on a fresh checkout,
// which would make a build step mandatory to run the tests.
//
//go:embed all:bin
var bin embed.FS

// Arches are the architectures komizo ships an agent for.
//
// Two, because they are what servers are. amd64 is every ordinary VPS, and
// arm64 is the cheap tier at most providers -- Hetzner, Oracle, AWS Graviton --
// which is exactly the tier a project running its own boxes ends up on.
var Arches = []string{"amd64", "arm64"}

// For returns the agent for one architecture.
func For(arch string) ([]byte, error) {
	b, err := bin.ReadFile("bin/komizo-box-linux-" + arch)
	if err != nil {
		return nil, fmt.Errorf("this komizo was built without a linux/%s agent.\n"+
			"    Built from source? Run `make agents`, then build again.\n"+
			"    Installed a release? Please report this -- the release is broken.", arch)
	}
	return b, nil
}

// ArchFor maps what `uname -m` says to what komizo builds.
//
// The box is asked rather than assumed. komizo is pointed at other people's
// servers, and a laptop's architecture says nothing about theirs -- installing
// an amd64 binary on an arm64 box produces "not found" from the kernel, which
// is the single most confusing thing an exec can say.
func ArchFor(uname string) (string, bool) {
	switch uname {
	case "x86_64", "amd64":
		return "amd64", true
	case "aarch64", "arm64":
		return "arm64", true
	}
	return "", false
}

// Stamp is the content hash of every agent this komizo carries.
//
// What it answers is "would running the update change anything" -- so it is
// over the bytes that would be installed, and it covers ALL architectures so
// that the same komizo produces the same stamp whatever box it is talking to.
// A per-architecture stamp would make two boxes disagree about whether they
// were up to date while running the same release.
//
// Empty when no agent is embedded, which reads as "nothing to install" rather
// than as a hash of nothing.
func Stamp() string {
	names := make([]string, 0, len(Arches))
	for _, a := range Arches {
		if _, err := bin.ReadFile("bin/komizo-box-linux-" + a); err == nil {
			names = append(names, a)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	h := sha256.New()
	for _, a := range names {
		b, _ := bin.ReadFile("bin/komizo-box-linux-" + a)
		h.Write([]byte(a))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
