package agent

import (
	"os"
	"strings"
	"testing"
)

// BOTH DOCUMENTED WAYS IN MUST WORK, and the README must show both.
//
// THIS CHECK HAS BEEN REVERSED, and the reversal is the point rather than an
// edit to tidy away.
//
// It was written for nicodes/komizo-be#177's first half: the README recommended
// `go install github.com/nicodes/komizo@latest`, and that produced a CLI which
// set up Docker, the shared network and the metadata block, then failed at the
// agent -- leaving a server provisioned and unreadable. So the rule was "never
// show the module form without saying it does not work".
//
// The second half removed the reason. A komizo with no embedded agent now
// compiles one from the same module at the same version, so `go run <module>@<v>
// init` is a working one-command start -- which is the bar a first-run
// experience should be held to, and the barrier was never acceptable.
//
// So the rule is now the opposite: the module form must be SHOWN, because it is
// the shortest true path, and the old warning must be GONE, because leaving it
// would tell people not to use the thing that works.

func TestTheReadmeShowsBothWaysIn(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	// A README that moved would pass every check below on an empty string.
	if len(readme) < 500 {
		t.Fatalf("README.md is %d bytes -- it moved, and this checked nothing", len(readme))
	}

	// THE ONE-COMMAND START. This is what somebody tries first, and it is the
	// only form that needs nothing downloaded beforehand.
	if !strings.Contains(readme, "go run github.com/nicodes/komizo@") {
		t.Error("README does not show the one-command start (`go run <module>@<version> init`), " +
			"which is the shortest working way in")
	}

	// AND THE NO-GO PATH, because a release archive carries the agents and needs
	// no toolchain at all. A README with only the module form leaves anybody
	// without Go with nothing.
	if !strings.Contains(readme, "gh release download") {
		t.Error("README does not show how to install from a release, which is the only " +
			"form that needs no Go toolchain")
	}

	// AND NOT THE OLD WARNING. It said the module form could not install an
	// agent. That was true and is not any more, and a stale warning is worse
	// than none: it tells people to avoid the path that works.
	if strings.Contains(readme, "`go install` does not work") {
		t.Error("README still says `go install` does not work -- it does now, since a " +
			"komizo with no embedded agent builds one from its own module version")
	}
}

// AND THE FAILURE THAT REMAINS NAMES A REMEDY THE READER CAN TAKE.
//
// There is still one case with no agent and no way to get one: a build with no
// module version to pin -- a checkout, or VCS stamping turned off. "Run `make
// agents`" is the right advice there, because that reader HAS a checkout.
func TestTheRemainingFailureNamesARemedyTheReaderCanTake(t *testing.T) {
	_, err := For("no-such-arch")
	if err == nil {
		t.Fatal("an architecture komizo does not ship returned an agent")
	}
	if !strings.Contains(err.Error(), "make agents") {
		t.Errorf("the missing-agent error does not name the remedy:\n%s", err)
	}
}
