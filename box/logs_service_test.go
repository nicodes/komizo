package box

import (
	"os"
	"path/filepath"
	"testing"
)

// WHICH SERVICE A COLLECTED LINE BELONGS TO.
//
// komizo#81. The collected file is one file per app with every service
// interleaved, and the only thing stating which service a line came from is
// compose's container prefix -- "web-gate-1  | ...". Getting this wrong puts
// one service's output on screen under another's name, which is worse than
// showing all of it.
func TestAServiceIsReadOffTheContainerPrefix(t *testing.T) {
	for _, tc := range []struct{ app, line, want string }{
		{"web", "web-gate-1  | started", "gate"},
		{"web", "web-api-2  | listening", "api"},
		// A service name may contain hyphens; only the replica number is last.
		{"web", "web-image-proxy-1  | ok", "image-proxy"},
		// Another app's line in this file belongs to no service here. It should
		// not be attributed to one by stripping the wrong prefix.
		{"web", "shop-gate-1  | started", ""},
		// No prefix at all: a continuation line, or something the collector did
		// not write.
		{"web", "just some output", ""},
		{"web", "", ""},
		// A prefix that is the app and nothing else has no replica number.
		{"web", "web-  | odd", ""},
	} {
		if got := ServiceOf(tc.app, tc.line); got != tc.want {
			t.Errorf("ServiceOf(%q, %q) = %q, want %q", tc.app, tc.line, got, tc.want)
		}
	}
}

// AND THE TAIL IS TAKEN AFTER THE FILTER, NOT BEFORE.
//
// Filtering a tail would return the last N lines of the APP and then show
// whichever happened to be this service -- on a busy neighbour, none of them.
// The screen would say the service had logged nothing while it was logging.
func TestTheTailIsOfTheServiceNotOfTheApp(t *testing.T) {
	dir := t.TempDir()
	var b []byte
	// One line from the service under test, then a hundred from a noisy one.
	b = append(b, []byte("web-api-1  | the line that matters\n")...)
	for range 100 {
		b = append(b, []byte("web-gate-1  | noise\n")...)
	}
	writeLog(t, dir, "web", b)

	got, err := ReadLogService(dir, "web", "api", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("the service's only line was tailed away by its neighbour's output")
	}
	if want := "web-api-1  | the line that matters"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// An unfiltered read is unchanged, so the narrowing cannot have been applied
// to callers that did not ask for it.
func TestAnUnfilteredReadStillSeesEveryService(t *testing.T) {
	dir := t.TempDir()
	writeLog(t, dir, "web", []byte("web-gate-1  | a\nweb-api-1  | b\n"))
	got, err := ReadLog(dir, "web", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got != "web-gate-1  | a\nweb-api-1  | b" {
		t.Errorf("an unfiltered read lost lines: %q", got)
	}
}

func writeLog(t *testing.T, dir, app string, body []byte) {
	t.Helper()
	p, err := LogPath(dir, app)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, 0o640); err != nil {
		t.Fatal(err)
	}
}
