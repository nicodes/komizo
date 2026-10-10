package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCapacityFreshnessRejectsMissingOldAndFutureReadings(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "report.json")
	for _, delta := range []time.Duration{0, -time.Minute, -3 * time.Minute, time.Second} {
		body, _ := json.Marshal(map[string]any{"at": now.Add(delta)})
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		err := workloadReportFresh(path, now)
		want := delta > 0 || delta < -2*time.Minute
		if (err != nil) != want {
			t.Fatalf("delta %s: %v", delta, err)
		}
	}
	for _, body := range []string{`{}`, `{"at":"invalid"}`, `garbage`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if workloadReportFresh(path, now) == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}
