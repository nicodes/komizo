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
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
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

// Get is the agent for one architecture, however this komizo can produce one.
//
// EMBEDDED FIRST, BUILT SECOND. A release archive carries the agents and needs
// no toolchain, which is what makes `komizo init` work on a machine with no Go
// on it. A `go install`/`go run` build carries none -- the agents are gitignored
// build artifacts, so the module the proxy serves has only bin/.keep -- and for
// that case the agent is compiled from the same module at the same version.
//
// modulePath and version are the running komizo's own, passed in rather than
// discovered here: this package must not be the thing that decides what version
// of itself to install, because getting that wrong installs an agent that does
// not match the CLI managing the box.
// The second return is the STAMP to record on the box -- what komizo installed
// there -- and it differs by path for a reason that matters.
//
// An embedded agent stamps by CONTENT, over every architecture, so the same
// release produces the same stamp whatever box it is talking to. A built one
// cannot: -trimpath and CGO_ENABLED=0 make the output reproducible across
// machines but not across TOOLCHAINS, so two operators on different Go versions
// would produce different bytes from identical source and each would read the
// other's box as out of date. Forever. That is precisely the never-settling
// false alarm this project keeps deleting.
//
// So a built agent stamps by VERSION, marked with a "v:" prefix so a reader can
// tell the two apart rather than comparing a hash against a version string and
// concluding something is wrong. Version is the honest identity here: the agent
// was compiled from a pinned module version, and that is exactly what decides
// whether running the update would change anything.
func Get(ctx context.Context, modulePath, version, arch string) ([]byte, string, error) {
	if b, err := For(arch); err == nil {
		return b, Stamp(), nil
	}
	if modulePath == "" || version == "" || !strings.HasPrefix(version, "v") {
		// A build with no module version: a checkout, or a binary compiled with
		// VCS stamping off. There is nothing to pin `go install` to, and
		// guessing a version would install an agent that need not match this
		// CLI at all.
		return nil, "", fmt.Errorf("this komizo carries no linux/%s agent and cannot work out "+
			"which version of one to build.\n"+
			"    Building from a checkout? Run `make agents`, then build again.\n"+
			"    Installed a release archive? Please report this -- the release is broken.", arch)
	}
	b, err := build(ctx, modulePath, version, arch)
	if err != nil {
		return nil, "", fmt.Errorf("this komizo carries no linux/%s agent, so it tried to build "+
			"one from %s@%s and could not:\n%w", arch, modulePath, version, err)
	}
	return b, BuiltStamp(version), nil
}

// BuiltStamp is what a compiled-on-demand agent records on the box.
//
// The "v:" prefix is load-bearing: it is how anything reading the stamp knows it
// is a version rather than a content hash, and therefore that comparing it to a
// hash says nothing. See agentBehind.
func BuiltStamp(version string) string {
	return "v:" + strings.TrimPrefix(version, "v")
}

// ByVersion reports whether a stamp names a version rather than hashing content.
func ByVersion(stamp string) bool { return strings.HasPrefix(stamp, "v:") }

// For returns the embedded agent for one architecture, and only that.
func For(arch string) ([]byte, error) {
	b, err := bin.ReadFile("bin/komizo-box-linux-" + arch)
	if err != nil {
		// NAMES THE go install CASE, because that is the one people reach.
		//
		// `go install github.com/nicodes/komizo@vX` and `go run ...@vX` are
		// SOURCE builds -- the module the proxy serves carries bin/.keep and
		// nothing else, since the binaries are gitignored build artifacts. So
		// they produce exactly this, and "run make agents" is advice the reader
		// cannot take: they have no checkout. The release archives are built by
		// a workflow that runs `make agents` first, which is why they work.
		return nil, fmt.Errorf("this komizo was built without a linux/%s agent.\n"+
			"    Installed with `go install` or run with `go run`? Those build from\n"+
			"    source, and the agents are not in the module -- they are built by\n"+
			"    `make agents`. Take a release archive instead:\n"+
			"        https://github.com/nicodes/komizo/releases\n"+
			"    Building from a checkout? Run `make agents`, then build again.\n"+
			"    Installed a release archive? Please report this -- the release is broken.", arch)
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
