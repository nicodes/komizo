package scripts

import (
	"strings"
	"testing"
)

// Reclaiming images no container is using.
//
// Nothing ever removed the image a deploy replaced. Every deploy and every
// preview pulls one tagged by commit, so two boxes reached 162 and 172
// images with 15 and 8 in use -- gdam alone holding fourteen copies of the
// same 157MB gate image from a single day. The capacity floor refused a
// preview before the disk filled, which is the only reason it surfaced as a
// failed preview rather than an outage.
//
// The app script says why it is not the place for this ("Disk is a SERVER
// concern. It belongs wherever server-wide upkeep ends up living") and this
// is that place.

func TestPruneIsServerLevelNotPerApp(t *testing.T) {
	// A machine-wide prune must not be reachable from the per-app path: that
	// one runs under a deploy key, and one app's deploy has no business
	// reaching across every other app on the box.
	//
	// CODE only. alpine.sh discusses `docker image prune` at length in a
	// comment explaining why it does not run one, and the first version of
	// this test matched that comment and failed on prose.
	for _, line := range strings.Split(AlpineScript, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		if strings.Contains(line, "image prune") {
			t.Errorf("the per-app script runs a machine-wide image prune, which a "+
				"deploy key can invoke: %s", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(AlpineInitScript, "docker image prune -af") {
		t.Error("the server script does not reclaim images")
	}
}

// -af, not -f. A bare `docker image prune` collects only DANGLING images,
// and a komizo deploy leaves none: every image it replaces is still tagged
// by its commit. The per-app script's own comment makes exactly this point.
func TestPruneCollectsTaggedImagesNotJustDangling(t *testing.T) {
	line := ""
	for _, l := range strings.Split(AlpineInitScript, "\n") {
		if strings.Contains(l, "docker image prune") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("no prune line found")
	}
	if !strings.Contains(line, "-af") {
		t.Errorf("prune must be -af; a bare prune collects only dangling images "+
			"and komizo leaves none: %s", line)
	}
	// No `until=` filter: the rule is "referenced by a container", not an age.
	// An age window keeps whatever happens to be recent, which is neither the
	// thing that is needed nor the thing that is safe.
	if strings.Contains(line, "until=") {
		t.Errorf("prune should keep what containers reference, not what is recent: %s", line)
	}
}

// The assumption underneath all of this -- that an image referenced by a
// STOPPED container survives `docker image prune -af`, so an app somebody
// stopped keeps the image it will start again with -- is Docker's documented
// behaviour, and was verified by hand against a real daemon before this
// landed. It is not re-tested here: doing so costs two minutes of CI to
// assert something Docker guarantees, and a test that slow gets skipped.
