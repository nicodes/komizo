package box

import (
	"encoding/json"
	"os"
	"testing"
)

// markerCase is one record both readers of the STOPPED marker must agree about.
//
// The table lives in ../testdata/stop_marker_cases.json and is read by this
// package and by scripts/deploy_stopped_test.go. Two hand-maintained copies kept
// in step by a comment was the previous arrangement, and deleting a case from
// either left the whole suite green -- including in the direction that matters,
// where the shell grows a case the Go reader was never asked about. See the
// README beside the fixture for why the two must agree at all.
type markerCase struct {
	Name    string `json:"name"`
	Record  string `json:"record"`
	Stopped bool   `json:"stopped"`
	Why     string `json:"why"`
}

func markerCases(t *testing.T) []markerCase {
	t.Helper()
	b, err := os.ReadFile("../testdata/stop_marker_cases.json")
	if err != nil {
		t.Fatalf("the shared marker cases are unreadable, so this test and the shell's would no longer be testing the same thing: %v", err)
	}
	var cs []markerCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	// A positive control on the fixture itself. An empty or truncated file would
	// otherwise turn every test built on it into a loop over nothing, which
	// passes.
	if len(cs) < 7 {
		t.Fatalf("only %d marker cases -- the shared table has shrunk, and both readers are now checked against less than they were", len(cs))
	}
	return cs
}
