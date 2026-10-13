package box

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestDeploymentFailuresAndAbandonedActivationAreReported(t *testing.T) {
	f := readyBox(t)
	now := f.probe().now()
	for _, tc := range []struct {
		phase string
		age   time.Duration
		want  bool
	}{
		{"activated", time.Hour, false}, {"prepared_stopped", time.Hour, false},
		{"activating", time.Minute, false}, {"activating", 11 * time.Minute, true},
		{"failed", 0, true}, {"activation_failed", 0, true},
	} {
		body, _ := json.Marshal(Deployment{Version: 1, App: "blog", Candidate: "release", Phase: tc.phase, At: now.Add(-tc.age)})
		f.write("/var/lib/komizo/releases/blog/operation.json", string(body))
		r := f.probe().Report(context.Background())
		found := false
		for _, p := range r.Problems {
			if p.Kind == ProblemDeploymentIncomplete {
				found = true
			}
		}
		if found != tc.want {
			t.Fatalf("phase %s age %s: %v", tc.phase, tc.age, r.Problems)
		}
	}
}

func TestDeploymentDiagnosisUsesProtectedDeadline(t *testing.T) {
	now := time.Now()
	for _, expired := range []bool{false, true} {
		deadline := now.Add(time.Minute)
		if expired {
			deadline = now.Add(-time.Second)
		}
		r := Report{At: now, Apps: []App{{Name: "fixture", Deployment: &Deployment{Phase: "activating", At: now.Add(-20 * time.Minute), Deadline: deadline}}}}
		found := false
		for _, p := range Diagnose(r) {
			if p.Kind == ProblemDeploymentIncomplete {
				found = true
			}
		}
		if found != expired {
			t.Fatalf("deadline expiration %v: %+v", expired, Diagnose(r))
		}
	}
}
