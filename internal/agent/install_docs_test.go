package agent

import (
	"os"
	"strings"
	"testing"
)

// THE README MUST NOT RECOMMEND AN INSTALL THAT CANNOT INSTALL AN AGENT.
//
// The agents are gitignored build artifacts -- `make agents` builds them and the
// release workflow runs it, but the module the Go proxy serves carries bin/.keep
// and nothing else. So `go install github.com/nicodes/komizo@vX` compiles
// happily and then fails at the one step that matters, AFTER Docker is
// installed, the network is made and the box is provisioned. It leaves a server
// set up and unreadable.
//
// The README recommended exactly that as its first command, and somebody
// followed it on a fresh box. This is a documentation defect with a
// half-provisioned machine at the end of it, which is why it gets a check rather
// than a correction: the sentence is easy to reintroduce and nothing else here
// would notice.
//
// The rule is not "never mention go install" -- from a CHECKOUT it is fine,
// because the Makefile builds the agents first. The rule is that the module form
// must never appear without the reason it does not work beside it.

func TestTheReadmeDoesNotRecommendAnInstallWithNoAgent(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	// A README that stopped existing, or moved, would pass every check below on
	// an empty string.
	if len(readme) < 500 {
		t.Fatalf("README.md is %d bytes -- it moved, and this checked nothing", len(readme))
	}

	// The module forms. `go install ./...` and `make build` inside a checkout are
	// a different thing and are not matched.
	const mod = "github.com/nicodes/komizo@"
	for _, verb := range []string{"go install " + mod, "go run " + mod} {
		if !strings.Contains(readme, verb) {
			continue
		}
		// PRESENT IS ALLOWED, UNEXPLAINED IS NOT. The failure this prevents is
		// somebody reading the command and not the caveat, so the caveat has to
		// be in the document at all.
		if !strings.Contains(readme, "does not work") {
			t.Errorf("README shows %q and never says it does not work -- that command "+
				"provisions a box and then cannot install its agent, which leaves the "+
				"server set up and unreadable", verb)
		}
		if !strings.Contains(readme, "make agents") {
			t.Errorf("README shows %q without naming `make agents`, which is what the "+
				"module form is missing", verb)
		}
	}

	// AND THE WORKING PATH IS THERE. A README that removed the broken command and
	// nothing else would pass everything above while telling nobody how to
	// install komizo.
	if !strings.Contains(readme, "gh release download") {
		t.Error("README does not show how to install from a release, which is the only " +
			"form that carries an agent")
	}
}

// AND THE FAILURE NAMES THE CASE PEOPLE ACTUALLY HIT.
//
// "Run `make agents`, then build again" is advice a `go install` user cannot
// take: they have no checkout. The message has to name the release.
func TestTheMissingAgentErrorNamesTheGoInstallCase(t *testing.T) {
	_, err := For("no-such-arch")
	if err == nil {
		t.Fatal("an architecture komizo does not ship returned an agent")
	}
	for _, want := range []string{"go install", "releases", "make agents"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the missing-agent error does not mention %q:\n%s", want, err)
		}
	}
}
