package main

import (
	"testing"

	"github.com/nicodes/komizo/box"
)

// THE WINDOW ROOTD KEEPS IS THE ONE IT ADVERTISES.
//
// Review 1 on komizo#83 showed MetricsWindow 1h -> 1m was green: a tick that
// computes the wrong window still writes a file, still decodes, and still
// serves 200 -- with most of the sparkline missing and nothing saying so.
func TestTheWindowRootdKeepsIsTheOneItAdvertises(t *testing.T) {
	if box.MetricsWindow != 60*60 {
		t.Errorf("MetricsWindow = %d, want an hour -- the app asks for half of one "+
			"and a reader who refreshes should not find the window moved under them",
			box.MetricsWindow)
	}
}

// WHAT IS STILL NOT ASSERTED, AND WHY, because a gap nobody wrote down is a gap
// nobody fixes.
//
// Review 1's B2: deleting the WriteMetrics call from rootd's tick leaves the
// suite green, and the route then answers 200 with no rows -- a box that served
// no traffic, on screen, indistinguishable from a working one.
//
// It cannot be driven from here today. runRootd calls PrepareStateDir with the
// CONSTANT box.StateDir rather than with anything derived from its flags, so a
// single tick demands /var/lib/komizo and fails under any account but root --
// which is also why this daemon has no tick test at all. Every other path in
// this file is flag-derived precisely so it can be pointed at a temp directory;
// this one was missed.
//
// Making the state directory flag-derived is the change that unblocks it, and
// it is not this PR's -- it touches how the daemon is invoked everywhere.
// komizo#84.
