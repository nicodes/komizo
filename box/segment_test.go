package box

import (
	"os/exec"
	"strings"
	"testing"
)

// LastSegment AGREES WITH THE SHELL, which is the third implementation.
//
// The parity test in internal/app compares the CLI against the box, and once
// both call this function it moves in lockstep with them -- so it can only
// notice a caller that STOPS using the helper, never a change to the helper
// itself. Review found exactly that: rewriting this to trim trailing slashes
// first, which is `path.Base`'s behaviour and the bug that was just removed,
// passed the whole suite.
//
// So this pins the semantics against something that cannot move with it:
// `${VAR##*/}` in scripts/alpine.sh, which is what actually runs on the box and
// decides what gets pulled. The same shape as charsets_test.go, and for the
// reason that file gives -- the shell stays the enforcement point and this
// becomes the agreement point.
func TestLastSegmentAgreesWithTheShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	for _, s := range []string{
		"ghcr.io/a/web",
		"ghcr.io/a/web:1",
		"ghcr.io/a/web:1/",
		"ghcr.io/a/web/",
		"reg.example.com:5000/a/web",
		"web",
		"web:1",
		"/web",
		"a//b",
		"a/",
		"/",
		"",
		".",
		"..",
		"a.b",
		"a:b/c",
	} {
		// ${VAR##*/} -- strip the longest prefix ending in "/". Passed in the
		// environment rather than interpolated, so the shell is doing the same
		// job on the same bytes rather than parsing a command we built.
		cmd := exec.Command("sh", "-c", `printf '%s' "${V##*/}"`)
		cmd.Env = append(cmd.Environ(), "V="+s)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got, want := LastSegment(s), string(out); got != want {
			t.Errorf("LastSegment(%q) = %q, the shell says %q.\n"+
				"    alpine.sh uses ${CONFIG_IMAGE##*/} to decide what gets pulled,\n"+
				"    so Go disagreeing with it is the divergence this function removed.",
				s, got, want)
		}
	}
}

// A TAG IS REFUSED WHEREVER IT IS, including with no registry in front of it.
//
// The corpus in internal/app only ever had tagged references WITH slashes, so
// making LastSegment return "" for a slashless value -- which would accept
// "web:1" -- passed everything.
func TestATagIsRefusedWithOrWithoutARegistry(t *testing.T) {
	for _, tagged := range []string{"web:1", "web:latest", "a/web:1", "ghcr.io/you/web:1"} {
		c := Command{V: CommandVersion, ID: "abc123", Srv: "srv_mine", Op: OpAppAdd,
			Args: map[string]string{
				"app":    "web",
				"config": tagged,
				"pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKD5vgfqmUVHAJDT5uZ6P+O/YBmR8hjj12T4jFnhrtqy deploy@web",
			}}
		if _, err := c.AddOf(); err == nil {
			t.Errorf("%q was accepted as a config image", tagged)
		} else if !strings.Contains(err.Error(), "tag") {
			t.Errorf("%q was refused for the wrong reason: %v", tagged, err)
		}
	}
}
