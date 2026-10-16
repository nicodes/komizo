//go:build race

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFixtureRaceHelper(t *testing.T) {
	if os.Getenv("KOMIZO_RACE_FIXTURE") != "1" {
		return
	}
	var value int
	var workers sync.WaitGroup
	start := make(chan struct{})
	for range 2 {
		workers.Go(func() {
			<-start
			for range 1000 {
				value++ // Deliberate race in this isolated negative control.
			}
		})
	}
	close(start)
	workers.Wait()
	os.Exit(0)
}

func TestFixtureProcessesStillRejectDataRaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race-fixture")
	if err := os.WriteFile(path, []byte(testProcessScript("TestFixtureRaceHelper", "KOMIZO_RACE_FIXTURE")), 0700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", path).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "WARNING: DATA RACE") {
		t.Fatalf("fixture race detector did not refuse the intentional race: %v\n%s", err, out)
	}
}
