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

// THE BOX IS NEVER WRITTEN. Reconcile's exact contact with a box is two seams,
// and both are stubbed and counted here:
//
//   - ensureReachable, the preflight every komizo command runs (`ssh ... true`
//     on the far end; LOCAL side effects are creating/tightening ~/.ssh to
//     0700 for the control socket and, only with --accept-host-key against a
//     box never seen before, appending to ~/.ssh/known_hosts), stubbed because
//     the real one opens SSH sessions and makes this a test of somebody's DNS;
//   - askBox, the one channel to the agent, through which the only verb this
//     command may send is a single "report".
//
// Anything further -- a piped script, a key rotation, a deploy, a provision --
// would go through one of these two and would fail the counts. Checked on a
// FAILING run as well as a passing one: a check that "helpfully" repaired what
// it found would only do so when something was wrong.
func TestReconcileDoesNotWriteProvisionRotateOrDeploy(t *testing.T) {
	for _, tc := range []struct {
		name string
		rep  box.Report
	}{
		{"when the box matches", registeredFixture()},
		{"when an app is missing", withoutApp(registeredFixture(), "termcade")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preflights := 0
			orig := ensureReachable
			ensureReachable = func(target, bool) error { preflights++; return nil }
			t.Cleanup(func() { ensureReachable = orig })
			asked := stubBox(t, func([]string) ([]byte, error) { return marshalBox(t, tc.rep), nil })
			_ = capture(t, func() {
				_ = RunReconcile([]string{"--host", "root@box", "--inventory", fixtureFile(t)})
			})

			if preflights != 1 {
				t.Fatalf("the reachability preflight ran %d times, want exactly one", preflights)
			}
			if len(*asked) != 1 {
				t.Fatalf("reconcile asked the agent %d times, want exactly one report fetch: %v", len(*asked), *asked)
			}
			if got := (*asked)[0]; len(got) != 1 || got[0] != "report" {
				t.Fatalf("reconcile sent %v to the agent; the only verb it may send is \"report\"", got)
			}
		})
	}
}

// AND THERE IS NO WRITE PATH TO REACH. The commands that change a box take a
// script runner or call target.runScript/quiet; RunReconcile's signature takes
// neither and its only agent call is fetchBox over askBox, asserted above.
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

	// AND A REPEATED EXPECTED HOSTNAME. The comparison is set-based, so a host
	// listed twice reads as one -- said twice, counted once, and nobody can
	// tell which was meant. Refused at load, where the author is looking.
	_, err = loadInventory(inventoryFile(t,
		`{"apps":[{"name":"blog","config":"ghcr.io/example/blog-config",
			"hosts":["blog.example.com","blog.example.com"]}]}`))
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a duplicate expected hostname was not refused: %v", err)
	}
}

// THE SIZE CAP BITES BEFORE THE ALLOCATION. The file is read through a
// LimitReader of inventoryMaxBytes+1, so inventoryMaxBytes+1 bytes on disk is
// the deliberate oversize: refused at the cap rather than after an unbounded
// read of a swapped-in blob.
func TestTheInventoryCapIsEnforcedOnTheWayIn(t *testing.T) {
	big := strings.Repeat(" ", inventoryMaxBytes+1)
	_, err := loadInventory(inventoryFile(t, big))
	if err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("a %d-byte inventory was not refused at the %d-byte cap: %v",
			inventoryMaxBytes+1, inventoryMaxBytes, err)
	}

	// AND EXACTLY AT THE CAP IS STILL READ, or the boundary is off by one in
	// the direction that rejects a legitimate file.
	doc := `{"apps":[{"name":"blog","config":"ghcr.io/example/blog-config","hosts":["blog.example.com"]}]}`
	if len(doc) >= inventoryMaxBytes {
		t.Fatal("the fixture document should be far under the cap")
	}
	padded := doc + strings.Repeat(" ", inventoryMaxBytes-len(doc))
	if _, err := loadInventory(inventoryFile(t, padded)); err != nil {
		t.Errorf("an inventory of exactly inventoryMaxBytes was refused: %v", err)
	}
}

// A DUPLICATE REGISTRATION CANNOT HIDE A MISMATCH. Last-write-wins indexing
// would let [blog(wrong), blog(expected)] pass an inventory expecting the
// correct config, because the second entry overwrote the first before the
// comparison ran. The control below is that exact arrangement, and the two
// orderings beside it: the duplicate is a finding either way, and the FIRST
// registration is the one compared.
func TestADuplicateRegisteredAppIsReportedRatherThanMasking(t *testing.T) {
	blog := func(config string) box.App {
		return box.App{Name: "blog", ConfigImage: config,
			Hosts: []box.Host{{Name: "blog.example.com"}}}
	}
	termcade := registeredFixture().Apps[1]

	inv := expectedFixture()

	// The masking control: wrong FIRST, then correct -- last-write-wins would
	// pass this silently.
	findings := reconcileInventory(inv, []box.App{
		blog("ghcr.io/example/wrong-config"), blog("ghcr.io/example/blog-config"), termcade})
	if !contains(findings, "duplicate registered app: blog") {
		t.Errorf("the duplicate was not reported: %v", findings)
	}
	if !contains(findings,
		"wrong config image for blog: expected ghcr.io/example/blog-config, registered ghcr.io/example/wrong-config") {
		t.Errorf("the FIRST registration was not the one compared: %v", findings)
	}

	// And the mirror: correct first, wrong second. The config comparison
	// passes, but the duplicate is still a finding -- a box reporting two apps
	// under one name is a fault in its own right.
	findings = reconcileInventory(inv, []box.App{
		blog("ghcr.io/example/blog-config"), blog("ghcr.io/example/wrong-config"), termcade})
	if len(findings) != 1 || findings[0] != "duplicate registered app: blog" {
		t.Errorf("findings = %v, want exactly the duplicate report", findings)
	}
}

// WILDCARDS ARE ROUTES TOO. The report schema carries them ("*.api.example.com"
// from an app on the proxy's on-demand-TLS gate), so the inventory can name
// one -- matched EXACTLY, string for string. Expanding a wildcard to bless
// whatever an app published under it would invert what an inventory is for.
func TestWildcardRoutesReconcileByExactMatch(t *testing.T) {
	// A wildcard survives the LOAD path, not just the in-memory comparison:
	// an inventory that cannot be written down is not support.
	if _, err := loadInventory(inventoryFile(t,
		`{"apps":[{"name":"api","config":"ghcr.io/example/api-config","hosts":["api.example.com","*.api.example.com"]}]}`)); err != nil {
		t.Fatalf("a valid wildcard inventory was refused at load: %v", err)
	}

	inv := expectedInventory{Apps: []expectedApp{
		{Name: "api", Config: "ghcr.io/example/api-config",
			Hosts: []string{"api.example.com", "*.api.example.com"}},
	}}
	matching := []box.App{{
		Name: "api", ConfigImage: "ghcr.io/example/api-config",
		Hosts: []box.Host{{Name: "api.example.com"}, {Name: "*.api.example.com"}},
	}}
	if got := reconcileInventory(inv, matching); len(got) != 0 {
		t.Errorf("an exactly matching wildcard route produced findings: %v", got)
	}

	// The wildcard and the concrete hostname are NOT interchangeable.
	concrete := []box.App{{
		Name: "api", ConfigImage: "ghcr.io/example/api-config",
		Hosts: []box.Host{{Name: "api.example.com"}, {Name: "a.api.example.com"}},
	}}
	got := reconcileInventory(inv, concrete)
	if !contains(got, "wrong hostname for api: *.api.example.com is expected but not a published route") {
		t.Errorf("a concrete hostname stood in for the wildcard: %v", got)
	}
	if !contains(got, "wrong hostname for api: a.api.example.com is a published route but not expected") {
		t.Errorf("the unexpected concrete route was not reported: %v", got)
	}
}

func TestWildcardInventoryEntriesAreValidated(t *testing.T) {
	for _, tc := range []struct {
		host, want string
	}{
		{"*", "must start with"},
		{"*api.example.com", "must start with"},
		{"a.*.example.com", "must start with"},
		{"*.*.example.com", "followed by a hostname"},
		{"*.", "followed by a hostname"},
	} {
		_, err := loadInventory(inventoryFile(t,
			`{"apps":[{"name":"api","config":"ghcr.io/example/api-config","hosts":["`+tc.host+`"]}]}`))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("wildcard %q: rejection = %v, want it to mention %q", tc.host, err, tc.want)
		}
	}
}

// ONE FILE, ONE DOCUMENT -- CHECKED AT THE STREAM, NOT THE CONTAINER. More()
// answers whether the array or object being parsed has another element; it is
// not an end-of-stream check. The strict check is a second Decode that must
// come back io.EOF, and both spellings of "there is more here" are refused.
func TestTheInventoryIsExactlyOneJSONDocument(t *testing.T) {
	doc := `{"apps":[{"name":"blog","config":"ghcr.io/example/blog-config"}]}`

	_, err := loadInventory(inventoryFile(t, doc+"\n"+doc))
	if err == nil || !strings.Contains(err.Error(), "second JSON document") {
		t.Errorf("a second document was not refused: %v", err)
	}

	_, err = loadInventory(inventoryFile(t, doc+" }}}"))
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Errorf("malformed trailing input was not refused: %v", err)
	}

	// AND TRAILING WHITESPACE IS FINE, or every editor that ends a file with a
	// newline just broke the check.
	if _, err := loadInventory(inventoryFile(t, doc+" \n\t\n")); err != nil {
		t.Errorf("trailing whitespace was refused: %v", err)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// A FIFO and symlink replacement tests live in reconcile_unix_test.go: the
// facilities are unix-only (Mkfifo, O_NOFOLLOW), and compiling them here would
// break the Windows build before any runtime skip could run.

// TWO FAULTS, TWO FINDINGS. A stray app registered twice is a duplicate
// registration AND an unexpected app -- one line for each, not three lines for
// two faults. This is the exact [blog, stray, stray] control: the duplicate
// group and the unexpected group each say their piece once.
func TestDuplicateUnexpectedRegistrationsAreCountedOnce(t *testing.T) {
	inv := expectedInventory{Apps: []expectedApp{
		{Name: "blog", Config: "ghcr.io/example/blog-config", Hosts: []string{"blog.example.com"}},
	}}
	stray := box.App{Name: "stray", ConfigImage: "ghcr.io/example/stray-config",
		Hosts: []box.Host{{Name: "stray.example.com"}}}
	blog := box.App{Name: "blog", ConfigImage: "ghcr.io/example/blog-config",
		Hosts: []box.Host{{Name: "blog.example.com"}}}

	got := reconcileInventory(inv, []box.App{blog, stray, stray})
	want := []string{
		"duplicate registered app: stray",
		"unexpected registered app: stray",
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("findings = %v, want exactly %v", got, want)
		}
	}
}

// THE TOP-LEVEL HELP TELLS THE SAME TRUTH AS THE SUBCOMMAND'S. An operator who
// reads only `komizo`'s own list must still learn that reconcile opens SSH
// sessions (the preflight and one report fetch), that connecting can create or
// tighten ~/.ssh for the control socket, and that --accept-host-key can append
// to the LOCAL known_hosts -- before running it, not after.
func TestTheTopLevelHelpStatesReconcilesExactContact(t *testing.T) {
	out := capture(t, Usage)
	for _, want := range []string{"reachability preflight", "report once", "~/.ssh", "known_hosts"} {
		if !strings.Contains(out, want) {
			t.Errorf("the top-level help does not mention %q:\n%s", want, out)
		}
	}
}
