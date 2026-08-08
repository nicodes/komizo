package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A KOMIZO WITH NO EMBEDDED AGENT CAN STILL PUT ONE ON A BOX.
//
// nicodes/komizo-be#177. `go run github.com/nicodes/komizo@vX init` set up
// Docker, the shared network and the metadata block, and then failed at the
// agent -- leaving a server provisioned and unreadable. The agents are
// gitignored build artifacts, so the module the Go proxy serves has none.
//
// THE BUILD IS REAL AND SO IS THIS TEST. It compiles the agent for real, from
// the module cache, because the failure being prevented is precisely "the
// mechanism does not work" -- and a test that stubbed the compiler would assert
// only that komizo calls something.
//
// Skipped when the network and module cache cannot supply the module: this
// resolves a versioned module, and a machine with neither is not one this can
// say anything about. The skip is LOUD about which case it is, so "all tests
// passed" never quietly means "the only test of this feature did not run".
func TestAKomizoWithNoEmbeddedAgentBuildsOne(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles a real binary; skipped under -short")
	}
	// TWO ARCHITECTURES, BECAUSE NEITHER ALONE CAN FAIL FOR EVERY REASON.
	//
	// arm64 is a real cross-compile from this runner, so it is the only one that
	// can catch GOARCH going missing. But a cross-compile disables cgo on its
	// own, so it CANNOT catch CGO_ENABLED=0 going missing -- the setting appears
	// either way. amd64 is native here, where cgo defaults to on, so it is the
	// only one that can.
	//
	// Both mutations survived a single-architecture version of this test, one
	// each. The fixture has to disagree with the wrong answer, and no single
	// fixture disagrees with both.
	//
	// The version is deliberately NOT the newest: building `@latest` produces
	// the current release, so pinning to the previous one is what tells a pinned
	// build from an unpinned one.
	const mod, version = "github.com/nicodes/komizo", "v0.0.16"

	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			b, err := build(context.Background(), mod, version, arch)
			if err != nil {
				if strings.Contains(err.Error(), "no Go toolchain") {
					t.Skip("no Go toolchain on this machine")
				}
				t.Fatalf("could not build the agent: %v", err)
			}
			if len(b) < 1<<20 {
				t.Fatalf("the agent is %d bytes, which is not a compiled binary", len(b))
			}

			// WHAT IT SAYS ABOUT ITSELF, which is the only assertion that can
			// tell a correct build from a plausible one. "an ELF binary over a
			// megabyte" was the first version and three mutations walked through
			// it. A Go binary records its GOOS, GOARCH and module version.
			f := filepath.Join(t.TempDir(), "agent")
			if err := os.WriteFile(f, b, 0o755); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("go", "version", "-m", f).CombinedOutput()
			if err != nil {
				t.Fatalf("go version -m: %v\n%s", err, out)
			}
			info := string(out)
			for _, want := range []string{
				// GOOS is asserted and is NOT independently discriminating on a
				// Linux runner: dropping it still yields GOOS=linux. Said
				// plainly rather than left to look like coverage it is not.
				// GOARCH below proves the cross-compile mechanism works, and
				// GOOS rides the same mechanism.
				"GOOS=linux",
				"GOARCH=" + arch,
				// Alpine: a binary linked against glibc will not run on the box.
				"CGO_ENABLED=0",
				// AND FROM THE VERSION IT WAS ASKED FOR.
				mod + "\t" + version,
			} {
				if !strings.Contains(info, want) {
					t.Errorf("the built agent does not record %q:\n%s", want, info)
				}
			}
		})
	}
}

// THE CROSS-COMPILED OUTPUT IS FOUND WHERE go install PUTS IT.
//
// `go install` writes to $GOBIN for a native build and $GOBIN/$GOOS_$GOARCH for
// a cross one. Looking only in $GOBIN finds nothing on every machine that is not
// already the target -- which is most of them, and would have made this feature
// work only on Linux amd64 developers' laptops.
func TestTheBuiltAgentIsFoundInTheCrossCompileDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "linux_arm64")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("\x7fELFpretend")
	if err := os.WriteFile(filepath.Join(sub, "komizo-box"), want, 0o755); err != nil {
		t.Fatal(err)
	}

	// THE REAL LOOKUP, not a copy of it. The first version of this restated
	// build()'s list of paths here, so deleting the cross-compile path from the
	// shipped code left this green -- a test asserting that a copy of the code
	// still agreed with itself.
	got, err := findBuilt(dir, "arm64")
	if err != nil {
		t.Fatalf("the cross-compiled agent was not found in $GOBIN/linux_arm64: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("found the wrong file: %q", got)
	}

	// AND $GOBIN ITSELF STILL WORKS, for the native case.
	native := t.TempDir()
	if err := os.WriteFile(filepath.Join(native, "komizo-box"), want, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := findBuilt(native, "amd64"); err != nil {
		t.Errorf("a native build in $GOBIN was not found: %v", err)
	}

	// AND AN EMPTY DIRECTORY IS AN ERROR, not an empty agent. Staging zero bytes
	// onto a box would install a file that is not a program.
	if _, err := findBuilt(t.TempDir(), "amd64"); err == nil {
		t.Error("an empty $GOBIN produced an agent")
	}
}

// WHAT Get DOES DEPENDS ON WHETHER THIS BUILD CARRIES AGENTS, AND BOTH ARE
// ASSERTED.
//
// The first version of this test assumed the embedded FS was empty and failed in
// the RELEASE, which runs `make agents` before its tests -- while CI, which does
// not, passed it. The same test saw two different worlds and only complained in
// one. That asymmetry is worth stating plainly: `.github/actions/build` runs
// `make agents` and `.github/actions/test` does not, so a test whose answer
// depends on embedded agents tells you about the pipeline it happened to run in.
//
// So this branches on the fact instead of assuming it, and each branch asserts
// the behaviour that matters there:
//
//   - agents embedded (a release build): Get hands one back and NEVER consults
//     the module version, because a release must not need a toolchain or a
//     network to set a box up.
//   - none embedded (a source build): Get refuses a reference it could not
//     resolve, rather than guessing a version and installing an agent that need
//     not match the CLI managing the box.
func TestGetPrefersAnEmbeddedAgentAndOtherwiseNeedsAVersion(t *testing.T) {
	_, embedded := For("amd64")
	hasEmbedded := embedded == nil

	for _, tc := range []struct{ name, path, version string }{
		{"no module path", "", "v0.0.17"},
		{"no version", "github.com/nicodes/komizo", ""},
		{"a version that is not one", "github.com/nicodes/komizo", "(devel)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, stamp, err := Get(context.Background(), tc.path, tc.version, "amd64")

			if hasEmbedded {
				// THE RELEASE CASE. An unusable module reference is irrelevant
				// when the agent is already carried, and Get must not fail over
				// one -- that would make a release archive need a toolchain.
				if err != nil {
					t.Fatalf("a komizo carrying agents refused to use one: %v", err)
				}
				if len(b) == 0 {
					t.Error("it returned no agent and no error")
				}
				if ByVersion(stamp) {
					t.Error("an embedded agent was stamped by version rather than by content")
				}
				return
			}

			// THE SOURCE-BUILD CASE.
			if err == nil {
				t.Fatal("it built an agent from a reference it could not have resolved")
			}
			// AND IT SAYS WHICH REMEDY APPLIES. "could not build" with no next
			// step is the shape this project keeps deleting.
			if !strings.Contains(err.Error(), "make agents") {
				t.Errorf("the refusal does not name the remedy:\n%v", err)
			}
		})
	}
}

// THE TWO KINDS OF STAMP ARE TOLD APART.
//
// A content hash and a version are both strings, and comparing one to the other
// always differs -- so a box set up by a built agent would read as out of date
// to a release komizo, and back again, forever.
func TestAVersionStampIsNotMistakenForAContentHash(t *testing.T) {
	built := BuiltStamp("v0.0.17")
	if !ByVersion(built) {
		t.Errorf("a built agent's stamp %q is not recognised as version-based", built)
	}
	if built != BuiltStamp("0.0.17") {
		t.Error("the leading v changes the stamp, so the same version stamps two ways")
	}
	// A content hash must NOT read as version-based, or the comparison abstains
	// on every box and the check stops working entirely.
	if ByVersion("0badc0ffee11") {
		t.Error("a content hash reads as version-based, which would disable the comparison")
	}
	if ByVersion("") {
		t.Error("an empty stamp reads as version-based")
	}
}
