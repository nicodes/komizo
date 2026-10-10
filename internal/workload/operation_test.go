package workload

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOperationIdentityDeadlineAndIllegalTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operation.json")
	now := time.Now().UTC()
	if err := RecordOperation(path, "example", "candidate", "previous", "ready", now); err == nil {
		t.Fatal("readiness manufactured without activation")
	}
	for _, phase := range []string{"admitted", "configured", "activating"} {
		if err := RecordOperation(path, "example", "candidate", "previous", phase, now); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var op Operation
	if err := json.Unmarshal(body, &op); err != nil {
		t.Fatal(err)
	}
	if len(op.ID) != 32 || !op.StartedAt.Equal(now) || !op.Deadline.Equal(now.Add(25*time.Minute)) {
		t.Fatal("lost bounded operation identity")
	}
	for _, request := range []struct {
		candidate, previous, phase string
		at                         time.Time
	}{
		{"candidate", "previous", "admitted", now}, // Same candidate still cannot replay ambiguous activation.
		{"candidate", "changed", "activated", now},
		{"candidate", "previous", "ready", now},
		{"candidate", "previous", "activated", now.Add(26 * time.Minute)},
	} {
		if err := RecordOperation(path, "example", request.candidate, request.previous, request.phase, request.at); err == nil {
			t.Fatalf("accepted invalid transition: %+v", request)
		}
	}
	if err := RecordOperation(path, "example", "candidate", "previous", "failed", now.Add(26*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := RecordOperation(path, "example", "candidate", "previous", "reconciled", now.Add(27*time.Minute)); err != nil {
		t.Fatal(err)
	}
}
