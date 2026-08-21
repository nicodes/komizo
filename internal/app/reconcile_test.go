package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// The registered-app fixture and the inventory it should match, built the way
// production builds its rows: the box side is a box.Report (what the agent
// sends), the expectation side is the file the operator keeps.
//
// Values are deliberately NOT production's. "termcade" is the app the check
// was written for (aviorstudio/termcade-be#49), so the app id is real; the
// image reference and hostnames are example fixtures, because this repository
// is not where production's routing facts live.

func expectedFixture() expectedInventory {
	return expectedInventory{Apps: []expectedApp{
		{Name: "blog", Config: "ghcr.io/example/blog-config", Hosts: []string{"blog.example.com"}},
		{Name: "termcade", Config: "ghcr.io/example/termcade-config",
			Hosts: []string{"termcade.example.com", "www.termcade.example.com"}},
	}}
}

// registeredFixture is the box, as a report, with every expected app present.
//
// A function rather than a package-level value so a test can mutate what it
// gets -- the deliberate-removal gate below removes termcade from its own
// copy -- without the next test inheriting the damage.
func registeredFixture() box.Report {
	return box.Report{
		V:      box.Version,
		At:     time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
		Server: box.Server{State: "ready", Docker: "Docker version 26"},
		Apps: []box.App{
			{
				Name: "blog", User: "komizo-blog", Dir: "/srv/blog",
				ConfigImage: "ghcr.io/example/blog-config",
				Hosts:       []box.Host{{Name: "blog.example.com"}},
			},
			{
				Name: "termcade", User: "komizo-termcade", Dir: "/srv/termcade",
				ConfigImage: "ghcr.io/example/termcade-config",
				Hosts: []box.Host{
					{Name: "termcade.example.com"},
					{Name: "www.termcade.example.com"},
				},
			},
		},
	}
}

// withoutApp is the fixture with one registration gone -- the state the
// rebuild left Termcade in.
func withoutApp(r box.Report, name string) box.Report {
	var kept []box.App
	for _, a := range r.Apps {
		if a.Name != name {
			kept = append(kept, a)
		}
	}
	r.Apps = kept
	return r
}

func marshalBox(t *testing.T, r box.Report) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// inventoryFile writes an inventory document and returns its path.
func inventoryFile(t *testing.T, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "expected-apps.json")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixtureFile(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(expectedFixture())
	if err != nil {
		t.Fatal(err)
	}
	return inventoryFile(t, string(b))
}

// runReconcile drives the real command against a stubbed box and returns its
// output (both streams) and error.
func runReconcile(t *testing.T, rep box.Report) (string, error) {
	t.Helper()
	reachable(t)
	stubBox(t, func([]string) ([]byte, error) { return marshalBox(t, rep), nil })
	var err error
	out := capture(t, func() {
		err = RunReconcile([]string{"--host", "root@box", "--inventory", fixtureFile(t)})
	})
	return out, err
}

// THE EXACT PASS. Inventory and box agree entry for entry, and the command
// says so and exits zero -- said, not silent, because an inspection that
// prints nothing on success is indistinguishable from one that never ran
// (komizo#47).
func TestReconcilePassesWhenTheBoxMatchesExactly(t *testing.T) {
	if got := reconcileInventory(expectedFixture(), registeredFixture().Apps); len(got) != 0 {
		t.Fatalf("a matching box produced findings: %v", got)
	}

	out, err := runReconcile(t, registeredFixture())
	if err != nil {
		t.Fatalf("reconcile against a matching box = %v\n%s", err, out)
	}
	if !strings.Contains(out, "all matching the inventory") {
		t.Errorf("a clean reconcile said nothing:\n%s", out)
	}
}

// MISSING TERMCADE. The fixture without its termcade registration is the
// state the rebuild left the box in, and the finding is the stable line the
// runbook greps for.
func TestReconcileReportsAMissingRegisteredApp(t *testing.T) {
	broken := withoutApp(registeredFixture(), "termcade")

	got := reconcileInventory(expectedFixture(), broken.Apps)
	if len(got) != 1 || got[0] != "missing registered app: termcade" {
		t.Fatalf("findings = %v, want exactly %q", got, "missing registered app: termcade")
	}

	out, err := runReconcile(t, broken)
	if err == nil {
		t.Fatalf("a box missing termcade exited 0:\n%s", out)
	}
	if !strings.Contains(out, "missing registered app: termcade") {
		t.Errorf("the finding is not in the output:\n%s", out)
	}
}

// AN APP THE INVENTORY NEVER HEARD OF. Rebuilds fail both ways: something
// expected can be absent, and something unexpected can be present.
func TestReconcileReportsAnUnexpectedRegisteredApp(t *testing.T) {
	rep := registeredFixture()
	rep.Apps = append(rep.Apps, box.App{
		Name: "stray", ConfigImage: "ghcr.io/example/stray-config",
		Hosts: []box.Host{{Name: "stray.example.com"}},
	})

	out, err := runReconcile(t, rep)
	if err == nil {
		t.Fatalf("an unexpected app exited 0:\n%s", out)
	}
	if !strings.Contains(out, "unexpected registered app: stray") {
		t.Errorf("the stray app was not reported:\n%s", out)
	}
}

func TestReconcileReportsAWrongConfigImage(t *testing.T) {
	rep := registeredFixture()
	for i := range rep.Apps {
		if rep.Apps[i].Name == "termcade" {
			rep.Apps[i].ConfigImage = "ghcr.io/example/other-config"
		}
	}

	out, err := runReconcile(t, rep)
	if err == nil {
		t.Fatalf("a wrong config image exited 0:\n%s", out)
	}
	want := "wrong config image for termcade: expected ghcr.io/example/termcade-config, registered ghcr.io/example/other-config"
	if !strings.Contains(out, want) {
		t.Errorf("the output does not carry %q:\n%s", want, out)
	}
}

// A WRONG HOSTNAME IS REPORTED FROM BOTH SIDES: the expected name that no
// route publishes, and the published route nobody expected. One without the
// other says only half of what changed.
func TestReconcileReportsAWrongHostname(t *testing.T) {
	rep := registeredFixture()
	for i := range rep.Apps {
		if rep.Apps[i].Name == "termcade" {
			rep.Apps[i].Hosts = []box.Host{{Name: "termca-de.example.net"}}
		}
	}

	out, err := runReconcile(t, rep)
	if err == nil {
		t.Fatalf("a wrong hostname exited 0:\n%s", out)
	}
	if !strings.Contains(out, "wrong hostname for termcade: termcade.example.com is expected but not a published route") {
		t.Errorf("the missing expected hostname was not reported:\n%s", out)
	}
	if !strings.Contains(out, "wrong hostname for termcade: termca-de.example.net is a published route but not expected") {
		t.Errorf("the unexpected published route was not reported:\n%s", out)
	}
}

// THE SCHEMA REFUSES SECRETS. Both spellings of the attempt: a FIELD the
// schema does not name -- "deploy_key" and friends are rejected by the strict
// decoder rather than kept -- and a VALUE that opens a PEM block, which no
// name, image reference or hostname can legitimately contain.
func TestTheInventoryRejectsSecretAndKeyLookingContent(t *testing.T) {
	for _, tc := range []struct {
		name, doc, want string
	}{
		{
			name: "a key-looking field",
			doc:  `{"apps":[{"name":"termcade","config":"ghcr.io/example/termcade-config","hosts":["termcade.example.com"],"deploy_key":"not-a-real-value"}]}`,
			want: "unknown field",
		},
		{
			name: "a secret-looking field",
			doc:  `{"apps":[{"name":"termcade","config":"ghcr.io/example/termcade-config","hosts":["termcade.example.com"],"secret":"x"}]}`,
			want: "unknown field",
		},
		{
			name: "key material as a value",
			doc: `{"apps":[{"name":"termcade","config":"ghcr.io/example/termcade-config",
				"hosts":["-----BEGIN OPENSSH PRIVATE KEY-----"]}]}`,
			want: "PEM",
		},
		{
			// And a private key SMUGGLED past the marker scan still dies on
			// the charset: no name, image or hostname may hold one.
			name: "a key-looking hostname",
			doc: `{"apps":[{"name":"termcade","config":"ghcr.io/example/termcade-config",
				"hosts":["PRIVATE KEY"]}]}`,
			want: "unexpected characters",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadInventory(inventoryFile(t, tc.doc))
			if err == nil {
				t.Fatal("an inventory carrying secret-looking content was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("rejection = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// THE COMMAND NEVER WRITES. Reconciliation is one read of the box's report and
// nothing else -- no script is piped, no key is rotated, nothing is deployed
// or provisioned. The proof is the stubbed boundary: every word this command
// sends to a box goes through askBox, and the stub records each call. More
// than one call, or any verb but "report", fails this test.
//
// Checked on a FAILING run as well as a passing one: a check that "helpfully"
// repaired what it found would only do so when something was wrong.
func TestReconcileDoesNotWriteProvisionRotateOrDeploy(t *testing.T) {
	for _, tc := range []struct {
		name string
		rep  box.Report
	}{
		{"when the box matches", registeredFixture()},
		{"when an app is missing", withoutApp(registeredFixture(), "termcade")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reachable(t)
			asked := stubBox(t, func([]string) ([]byte, error) { return marshalBox(t, tc.rep), nil })
			_ = capture(t, func() {
				_ = RunReconcile([]string{"--host", "root@box", "--inventory", fixtureFile(t)})
			})

			if len(*asked) != 1 {
				t.Fatalf("reconcile addressed the box %d times, want exactly one read: %v", len(*asked), *asked)
			}
			if got := (*asked)[0]; len(got) != 1 || got[0] != "report" {
				t.Fatalf("reconcile sent %v to the box; the only verb it may send is \"report\"", got)
			}
		})
	}
}

// AND THERE IS NO WRITE PATH TO REACH. The commands that change a box take a
// script runner or call target.runScript/quiet; RunReconcile's signature takes
// neither and its only box call is fetchBox over askBox, asserted above.
// This test is the executable half of that claim; the other half is that
// "reconcile" appears nowhere in scripts/ and its command function has no
// runner parameter.

// OPERATOR ONLY. A per-app deploy account is locked to its two privileged
// commands, so a reconcile through one would fail on the far end with a
// message about the wrong thing -- refuse it here instead.
func TestReconcileRefusesADeployAccount(t *testing.T) {
	reachable(t)
	called := false
	stubBox(t, func([]string) ([]byte, error) { called = true; return nil, nil })
	err := RunReconcile([]string{"--host", "komizo-termcade@box", "--inventory", fixtureFile(t)})
	if err == nil || !strings.Contains(err.Error(), "deploy account") {
		t.Fatalf("a deploy-account login was not refused: %v", err)
	}
	if called {
		t.Error("the box was contacted before the deploy account was refused")
	}
}

// The smaller guards: a missing --inventory flag, a duplicate app, and a
// config reference carrying a tag (the deploy supplies tags; the inventory
// pins the repository, as the box's own validation does).
func TestReconcileRequiresAnInventory(t *testing.T) {
	if err := RunReconcile([]string{"--host", "root@box"}); err == nil ||
		!strings.Contains(err.Error(), "--inventory is required") {
		t.Fatalf("no --inventory was not refused: %v", err)
	}
}

func TestTheInventoryRejectsDuplicatesAndTaggedImages(t *testing.T) {
	_, err := loadInventory(inventoryFile(t,
		`{"apps":[{"name":"blog","config":"ghcr.io/example/blog-config"},
		          {"name":"blog","config":"ghcr.io/example/blog-config"}]}`))
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a duplicate app was not refused: %v", err)
	}

	_, err = loadInventory(inventoryFile(t,
		`{"apps":[{"name":"blog","config":"ghcr.io/example/blog-config:v1"}]}`))
	if err == nil || !strings.Contains(err.Error(), "tag") {
		t.Errorf("a tagged config image was not refused: %v", err)
	}
}
