package agent

import (
	"strings"
	"testing"
)

// What `uname -m` says, mapped to what komizo builds.
//
// The box is asked rather than assumed, because komizo is pointed at other
// people's servers and a laptop's architecture says nothing about theirs. The
// failure this prevents is the worst-sounding one an exec can produce: an amd64
// binary on an arm64 box reports "not found" about a file that plainly exists.
func TestArchFor(t *testing.T) {
	for uname, want := range map[string]string{
		"x86_64":  "amd64",
		"amd64":   "amd64",
		"aarch64": "arm64",
		"arm64":   "arm64",
	} {
		got, ok := ArchFor(uname)
		if !ok || got != want {
			t.Errorf("ArchFor(%q) = %q, %v; want %q", uname, got, ok, want)
		}
	}
	// Anything else is refused rather than guessed. A wrong guess installs a
	// binary the kernel cannot run.
	for _, uname := range []string{"armv7l", "i686", "riscv64", "", "x86_64\n"} {
		if _, ok := ArchFor(uname); ok {
			t.Errorf("ArchFor(%q) claimed an architecture komizo does not ship", uname)
		}
	}
}

// A komizo built without `make agents` still works for everything except
// installing one, and says exactly that when asked. The alternative -- a build
// that fails, or one that ships an empty file -- would make the build step
// mandatory to run the tests, or put a zero-byte binary on somebody's server.
func TestAMissingAgentSaysWhatToDo(t *testing.T) {
	if _, err := For("sparc64"); err == nil {
		t.Fatal("want an error for an architecture with no embedded agent")
	} else if want := "make agents"; !strings.Contains(err.Error(), want) {
		t.Errorf("the error should say %q, got %q", want, err)
	}
}

// The stamp answers "would running the update change anything", so it is over
// the bytes that would be installed -- and over ALL of them, so the same komizo
// reports the same stamp whatever box it is talking to.
func TestStampCoversEveryAgentOrNone(t *testing.T) {
	got := Stamp()
	if got == "" {
		// Built without `make agents`. Empty rather than a hash of nothing,
		// which is the honest answer for a komizo with no agent to install.
		for _, a := range Arches {
			if _, err := For(a); err == nil {
				t.Errorf("no stamp, but linux/%s is embedded", a)
			}
		}
		t.Skip("no agents embedded; run `make agents`")
	}
	if len(got) != 12 {
		t.Errorf("stamp = %q, want 12 characters", got)
	}
	if got != Stamp() {
		t.Error("the stamp is not stable between calls")
	}
	// Every architecture komizo claims to ship is actually there. A release
	// missing one would otherwise be discovered by whoever ran init on an arm
	// box.
	for _, a := range Arches {
		b, err := For(a)
		if err != nil {
			t.Errorf("linux/%s: %v", a, err)
			continue
		}
		if len(b) < 1<<20 {
			t.Errorf("linux/%s is %d bytes -- too small to be a Go binary", a, len(b))
		}
		// ELF, and nothing else. A shell script or a build-cache artefact here
		// would install cleanly and fail on the box.
		if len(b) < 4 || string(b[:4]) != "\x7fELF" {
			t.Errorf("linux/%s is not an ELF binary", a)
		}
	}
}
