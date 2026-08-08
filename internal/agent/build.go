package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Building the agent when this komizo does not carry one.
//
// nicodes/komizo-be#177. `go install github.com/nicodes/komizo@vX` and
// `go run ...@vX` are SOURCE builds, and the agents are gitignored build
// artifacts -- so the module the Go proxy serves has none. That produced a CLI
// which set up Docker, the shared network and the metadata block, and then
// failed at the agent, leaving a server provisioned and unreadable.
//
// A ONE-COMMAND START IS THE REQUIREMENT. `go run <module>@<version> init` is
// how somebody tries this for the first time, and "download an archive first"
// is a barrier at exactly the wrong moment.
//
// SO IT IS BUILT, NOT FETCHED, AND THAT IS THE SECURITY DECISION.
//
// The agent is compiled from THE SAME MODULE AT THE SAME VERSION as the komizo
// that is running. Not a release asset, not a URL, not a hash pinned in a file
// that has to be kept in step -- the module the operator has already chosen to
// execute. There is no second supply chain to trust, because there is no second
// artifact: `go install <module>/cmd/komizo-box@<this version>` resolves through
// the operator's own toolchain and is verified against Go's checksum database,
// the same transparency log that vouched for the komizo they are already
// running. Anything that could tamper with the agent could already have
// tampered with the CLI, which is a strictly smaller claim than adding a
// download to `komizo init`.
//
// design/appify.md rejected FETCHING the agent, and this is not that. Nothing
// new is reached over the network that was not already reached to get here, and
// on a machine whose module cache is warm nothing is reached at all.

// buildTimeout bounds the compile.
//
// Generous, because a cold module cache means downloading the module and
// compiling it, on whatever the operator's machine is. Bounded at all because
// this runs inside `komizo init`, and a build that hangs would hang the setup
// with no way to tell it from a slow one.
const buildTimeout = 5 * time.Minute

// goBuildEnv is the environment the agent is compiled in.
//
// CGO_ENABLED=0 because the box is Alpine: a binary linked against glibc will
// not run there, and the failure is the kernel saying "not found" about a file
// that plainly exists.
//
// NOTHING HERE WEAKENS VERIFICATION. GOFLAGS, GONOSUMDB, GOPRIVATE and
// GONOSUMCHECK are deliberately not set: the checksum database is the whole
// reason this is safe, and a komizo that quietly disabled it while claiming
// otherwise would be the worst version of this feature. The operator's own
// settings are inherited, which is the same trust they already extended by
// running `go run` at all.
func goBuildEnv(arch string) []string {
	return append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+arch,
	)
}

// build compiles the agent for one architecture, at one module version.
//
// version is the module version of the running komizo -- "v0.0.17", with the
// leading v. PINNED, never `@latest`: a komizo that installed whatever the
// newest agent happened to be would put a box out of step with the CLI managing
// it, and would make what gets installed depend on when you ran it.
func build(ctx context.Context, modulePath, version, arch string) ([]byte, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("no Go toolchain on this machine to build the agent with")
	}

	// A THROWAWAY MODULE, AND NOT `go install pkg@version`.
	//
	// That was the obvious form and it is unusable here: `go install` REFUSES to
	// cross-compile when GOBIN is set --
	//
	//     go: cannot install cross-compiled binaries when GOBIN is set
	//
	// -- and without GOBIN it writes into the operator's own GOPATH/bin, which
	// installing komizo has no business doing. Every agent build is a cross
	// build unless the operator happens to be on linux/<the box's arch>, so that
	// form works on a Linux amd64 laptop and fails on every Mac.
	//
	// It took a mutation to find: the first test built for the host's own
	// architecture, where nothing crosses and `go install` is happy.
	//
	// A one-file module requiring the version, built with `go build -o`, has
	// none of that. It shares the operator's module cache, so a warm cache
	// reaches the network not at all.
	dir, err := os.MkdirTemp("", "komizo-agent-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	gomod := fmt.Sprintf("module komizo-agent-build\n\ngo 1.26\n\nrequire %s %s\n", modulePath, version)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()

	// DOWNLOAD FIRST, so go.sum is written and the module is checked against
	// Go's checksum database before anything compiles it. Skipping this and
	// letting the build resolve would still verify -- but doing it as its own
	// step is what makes the failure say "this module did not verify" rather
	// than burying it in a compile error.
	dl := exec.CommandContext(ctx, goBin, "mod", "download", modulePath)
	dl.Dir = dir
	dl.Env = goBuildEnv(arch)
	if out, err := dl.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("could not fetch %s@%s:\n%s", modulePath, version, indent(string(out)))
	}

	// THE SAME FLAGS THE Makefile USES, so a komizo built either way installs
	// the same bytes wherever the toolchain matches. -trimpath removes the build
	// machine's paths, which is what makes that possible at all.
	out := filepath.Join(dir, "komizo-box")
	cmd := exec.CommandContext(ctx, goBin, "build",
		"-trimpath",
		"-ldflags", "-s -w -X main.version="+strings.TrimPrefix(version, "v"),
		"-o", out,
		modulePath+"/cmd/komizo-box")
	cmd.Dir = dir
	cmd.Env = goBuildEnv(arch)

	if b, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("building the agent took longer than %s", buildTimeout)
		}
		return nil, fmt.Errorf("could not build the agent for linux/%s:\n%s", arch, indent(string(b)))
	}
	return findBuilt(dir, arch)
}

// findBuilt reads what the build left.
//
// `go build -o` puts it exactly where it was told, so this is one path now. The
// second is kept for the shape `go install` produces -- $GOBIN/$GOOS_$GOARCH for
// a cross build -- because that form is what somebody reaching for the obvious
// implementation will write, and finding nothing is a worse failure than
// looking in two places.
//
// Its own function so a test can assert WHERE it looks without paying for a
// compile to find out. The first version of that test restated this list
// instead of calling it, and deleting a path left it green.
func findBuilt(dir, arch string) ([]byte, error) {
	for _, p := range []string{
		filepath.Join(dir, "komizo-box"),
		filepath.Join(dir, "linux_"+arch, "komizo-box"),
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("the agent built for linux/%s and left nothing behind", arch)
}

func indent(s string) string {
	var b strings.Builder
	for _, ln := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    ")
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}
