package workload

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadinessRequiresCandidateContainersAndCandidateRoute(t *testing.T) {
	candidate := strings.Repeat("a", 40)
	for _, scenario := range []string{"ready", "old-image", "old-route", "old-product", "unhealthy", "absent", "wrong-project", "migration-failed", "migration-complete", "dependency-unready"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				revision := candidate
				if scenario == "old-route" {
					revision = strings.Repeat("b", 40)
				}
				w.Header().Set("X-Komizo-Revision", revision)
				if scenario == "dependency-unready" {
					w.WriteHeader(503)
				}
				if scenario == "old-product" {
					revision = strings.Repeat("b", 40)
				}
				fmt.Fprintf(w, `{"revision":%q}`, revision)
			}))
			defer server.Close()
			p := testPolicy(t)
			p.Readiness = &ReadinessPolicy{Probes: []ReadinessProbe{{URL: server.URL, RevisionField: "revision"}}}
			run := func(_ context.Context, args ...string) (string, error) {
				switch args[0] {
				case "compose":
					if scenario == "absent" {
						return "", nil
					}
					return strings.Repeat("c", 64), nil
				case "image":
					return "sha256:candidate", nil
				case "inspect":
					c := readyContainer{Service: "gate", Project: p.App, Image: "sha256:candidate", Status: "running", Health: "healthy"}
					if scenario == "old-image" {
						c.Image = "sha256:previous"
					}
					if scenario == "wrong-project" {
						c.Project = "neighbour"
					}
					if scenario == "unhealthy" {
						c.Health = "unhealthy"
					}
					if strings.HasPrefix(scenario, "migration-") {
						c.Status = "exited"
						c.Health = ""
						if scenario == "migration-failed" {
							c.ExitCode = 1
						}
					}
					body, _ := json.Marshal(c)
					return string(body), nil
				}
				return "", fmt.Errorf("unexpected command")
			}
			err := VerifyReadiness(context.Background(), run, server.Client(), p, candidate, "/approved/compose.yml", []byte(`{"services":{"gate":{"image":"approved:candidate","restart":"no"}}}`))
			accepted := scenario == "ready" || scenario == "migration-complete"
			if (err == nil) != accepted {
				t.Fatalf("accepted=%v, error=%v", accepted, err)
			}
		})
	}
}

func TestReadinessCancellationAndOperatorProbeAuthority(t *testing.T) {
	p := testPolicy(t)
	p.Readiness = &ReadinessPolicy{Probes: []ReadinessProbe{{URL: "https://product.example/ready"}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run := func(ctx context.Context, _ ...string) (string, error) { return "", ctx.Err() }
	if VerifyReadiness(ctx, run, &http.Client{}, p, strings.Repeat("a", 40), "/approved", []byte(`{"services":{"gate":{"image":"approved"}}}`)) == nil {
		t.Fatal("cancelled readiness accepted")
	}
	for _, url := range []string{"http://product.example/", "https://user:secret@product.example/", "https://product.example/?secret=value"} {
		if (ReadinessPolicy{Probes: []ReadinessProbe{{URL: url}}}).Check() == nil {
			t.Fatal("unreviewable probe accepted")
		}
	}
}

func TestIngressIsolationPreservesLongAppIdentity(t *testing.T) {
	a := strings.Repeat("a", 40) + "first"
	b := strings.Repeat("a", 40) + "second"
	if IsolatedIngress(a) == IsolatedIngress(b) {
		t.Fatal("different apps share ingress")
	}
	p := testPolicy(t)
	p.IngressNetwork = IsolatedIngress(p.App)
	body, err := Validate(strings.NewReader(basic), p, "candidate")
	if err != nil || !strings.Contains(string(body), p.IngressNetwork) {
		t.Fatalf("private ingress missing: %s %v", body, err)
	}
}
