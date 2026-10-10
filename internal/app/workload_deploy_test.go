package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/workload"
)

func TestDeployWorkloadHelper(t *testing.T) {
	if os.Getenv("KOMIZO_WORKLOAD_TEST_HELPER") != "1" {
		return
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	if len(args) > 1 && args[0] == "workload" && args[1] != "validate" {
		var output, compose, report string
		for i := 2; i < len(args)-1; i++ {
			if args[i] == "--output" {
				output = args[i+1]
			}
			if args[i] == "--report" {
				report = args[i+1]
			}
			if args[i] == "--compose" {
				compose = args[i+1]
			}
		}
		switch args[1] {
		case "activation-idle":
		case "activation-submit":
			fmt.Println("01234567890123456789012345678901")
		case "activation-wait":
			fmt.Println("deploy: started=yes")
		case "ingress-name":
			fmt.Println("edge")
		case "ready": // fixture policies deliberately have no product probes
		case "release-admit":
			if err := os.WriteFile(output, []byte(`{}`), 0600); err != nil {
				os.Exit(1)
			}
		case "release-bind":
			body, err := os.ReadFile(compose)
			if err != nil {
				os.Exit(1)
			}
			if err := os.WriteFile(output, body, 0600); err != nil {
				os.Exit(1)
			}
		case "capacity":
			body, err := os.ReadFile(report)
			var r struct {
				At time.Time `json:"at"`
			}
			if err != nil || json.Unmarshal(body, &r) != nil || r.At.IsZero() || r.At.After(time.Now()) || time.Since(r.At) > 2*time.Minute {
				os.Exit(1)
			}
		case "operation":
		default:
			os.Exit(2)
		}
		os.Exit(0)
	}
	if len(args) < 2 || args[0] != "workload" || args[1] != "validate" {
		os.Exit(2)
	}
	fs := flag.NewFlagSet("workload", flag.ContinueOnError)
	policy := fs.String("policy", "", "")
	compose := fs.String("compose", "", "")
	output := fs.String("output", "", "")
	version := fs.String("version", "", "")
	fs.String("app", "", "")
	fs.String("app-dir", "", "")
	fail := func(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	if err := fs.Parse(args[2:]); err != nil {
		fail(err)
	}
	pfile, err := os.Open(*policy)
	if err != nil {
		fail(err)
	}
	p, err := workload.ReadPolicy(pfile)
	_ = pfile.Close()
	if err != nil {
		fail(err)
	}
	file, err := os.Open(*compose)
	if err != nil {
		fail(err)
	}
	data, err := workload.Validate(file, p, *version)
	_ = file.Close()
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*output, data, 0600); err != nil {
		fail(err)
	}
	os.Exit(0)
}

func TestHostWorkloadRejectionLeavesDeploymentUntouched(t *testing.T) {
	for _, unsafe := range []string{
		"    privileged: true\n", "    volumes: [/:/host]\n", "    network_mode: host\n", "    env_file: [/etc/private]\n",
	} {
		t.Run(strings.TrimSpace(unsafe), func(t *testing.T) {
			b := newDeployBox(t)
			oldCompose := "services: {}\n# serving configuration\n"
			write(t, filepath.Join(b.appDir, "compose.yml"), 0600, oldCompose)
			oldRoute := "old.example { reverse_proxy blog-gate:80 }\n"
			write(t, filepath.Join(b.routes, "blog.caddy"), 0644, oldRoute)
			write(t, filepath.Join(b.appDir, ".env"), 0600, "APP_VERSION=old\n")
			b.publishes(t, "services:\n  api:\n    image: ghcr.io/you/blog-api:abc123\n"+unsafe, "new.example\n")
			out, err := b.deploy(t, "abc123")
			if err == nil || !strings.Contains(out, "host workload policy") {
				t.Fatalf("unsafe deployment not refused: %v %s", err, out)
			}
			for path, expected := range map[string]string{filepath.Join(b.appDir, "compose.yml"): oldCompose, filepath.Join(b.routes, "blog.caddy"): oldRoute, filepath.Join(b.appDir, ".env"): "APP_VERSION=old\n"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != expected {
					t.Fatalf("refusal changed installed state: %s", path)
				}
			}
		})
	}
}
