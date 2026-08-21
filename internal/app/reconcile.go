package app

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nicodes/komizo/box"
)

// `komizo reconcile` -- does this box hold exactly the apps the inventory says
// it must?
//
// INSPECTION ONLY. The whole command is one read of the box's report through
// the agent, compared against a local file. It provisions nothing, deploys
// nothing, rotates no key and changes no setting: after a host rebuild it is
// the check that answers "did everything expected come back" BEFORE anyone
// starts re-adding apps by hand. See the README's rebuild section.
//
// The inventory is deliberately thin: an app's name, its pinned config-image
// reference, and the public hostnames it is expected to publish. Anything
// beyond that -- a deploy key, a token, a secret of any spelling -- is
// REJECTED at load, so the file stays safe to commit next to the runbooks
// that use it. The schema refusing extra fields is the guard: an inventory
// that quietly accepted a "deploy_key" entry would become the place keys go
// to be leaked.

// inventoryMaxBytes caps the file. It is a list of a handful of apps; a
// megabyte is a thousand times what one needs, and the cap turns a swapped-in
// blob of something else into an error instead of a slow parse.
const inventoryMaxBytes = 1 << 20

// expectedApp is the one line the inventory holds per app: nothing an attacker
// could use, everything a rebuild check needs.
type expectedApp struct {
	Name   string   `json:"name"`
	Config string   `json:"config"`
	Hosts  []string `json:"hosts"`
}

// expectedInventory is the whole file.
type expectedInventory struct {
	Apps []expectedApp `json:"apps"`
}

// keyMaterialMarker is what a PEM block opens with. An inventory value can
// never legitimately contain one -- names, image references and hostnames all
// reject the spaces and dashes long before this -- so finding it means the
// file is carrying key material and must be refused whole rather than picked
// apart field by field.
const keyMaterialMarker = "-----BEGIN"

// loadInventory reads and validates the expected-app file.
//
// Strict, on purpose. DisallowUnknownFields is what rejects a
// secret-looking field -- "deploy_key", "token", anything the schema does not
// name -- instead of silently keeping it in a file people commit.
func loadInventory(path string) (expectedInventory, error) {
	var inv expectedInventory
	raw, err := os.ReadFile(path)
	if err != nil {
		return inv, fmt.Errorf("could not read the inventory: %w", err)
	}
	if len(raw) > inventoryMaxBytes {
		return inv, fmt.Errorf("the inventory is over %d bytes -- it is a short list of apps, not a data dump", inventoryMaxBytes)
	}
	if bytes.Contains(raw, []byte(keyMaterialMarker)) {
		return inv, fmt.Errorf("the inventory contains what looks like a PEM block (%q);\n"+
			"    it may hold only app names, config-image references and public hostnames.\n"+
			"    Keys, tokens and secrets never belong in it.", keyMaterialMarker+" ...")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return inv, fmt.Errorf("the inventory carries a field the schema does not allow: %w\n"+
				"    Only \"name\", \"config\" and \"hosts\" exist. A secret, token or key field\n"+
				"    is refused here so this file stays safe to commit.", err)
		}
		return inv, fmt.Errorf("could not parse the inventory: %w", err)
	}
	// Trailing data after the document is a second document, which is how one
	// file quietly becomes two inventories.
	if dec.More() {
		return inv, fmt.Errorf("the inventory has data after the document -- one file, one inventory")
	}

	seen := map[string]bool{}
	for _, a := range inv.Apps {
		if seen[a.Name] {
			return inv, fmt.Errorf("the inventory names %q twice", a.Name)
		}
		seen[a.Name] = true
		if err := validateApp(a.Name); err != nil {
			return inv, fmt.Errorf("inventory: %w", err)
		}
		if err := validateConfigImage(a.Config); err != nil {
			return inv, fmt.Errorf("inventory for %q: %w", a.Name, err)
		}
		for _, h := range a.Hosts {
			if err := validateHost(h); err != nil {
				return inv, fmt.Errorf("inventory for %q: %w", a.Name, err)
			}
		}
	}
	return inv, nil
}

// reconcileInventory is the comparison, with the IO nowhere near it: what the
// inventory expects against what the box registered, one finding per
// disagreement. Empty is the only pass.
//
// The messages are stable on purpose -- `missing registered app: <name>` is
// the line a rebuild runbook greps for, and a message that drifts between
// releases breaks the check that watches for it.
func reconcileInventory(inv expectedInventory, registered []box.App) []string {
	byName := make(map[string]box.App, len(registered))
	for _, a := range registered {
		byName[a.Name] = a
	}

	var findings []string

	// Sorted, so two runs over the same mismatch print the same lines in the
	// same order -- a diff between yesterday's check and today's should be the
	// change, not the ordering.
	expected := append([]expectedApp(nil), inv.Apps...)
	sort.Slice(expected, func(i, j int) bool { return expected[i].Name < expected[j].Name })

	for _, e := range expected {
		a, ok := byName[e.Name]
		if !ok {
			findings = append(findings, "missing registered app: "+e.Name)
			continue
		}
		if a.ConfigImage != e.Config {
			findings = append(findings, fmt.Sprintf(
				"wrong config image for %s: expected %s, registered %s", e.Name, e.Config, a.ConfigImage))
		}
		routes := map[string]bool{}
		for _, h := range a.Routes() {
			routes[h] = true
		}
		want := map[string]bool{}
		for _, h := range e.Hosts {
			want[h] = true
			if !routes[h] {
				findings = append(findings, fmt.Sprintf(
					"wrong hostname for %s: %s is expected but not a published route", e.Name, h))
			}
		}
		for _, h := range a.Routes() {
			if !want[h] {
				findings = append(findings, fmt.Sprintf(
					"wrong hostname for %s: %s is a published route but not expected", e.Name, h))
			}
		}
	}

	var extra []string
	for _, a := range registered {
		if !seenIn(inv, a.Name) {
			extra = append(extra, a.Name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		findings = append(findings, "unexpected registered app: "+name)
	}
	return findings
}

func seenIn(inv expectedInventory, name string) bool {
	for _, a := range inv.Apps {
		if a.Name == name {
			return true
		}
	}
	return false
}

func RunReconcile(args []string) error {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	fs.Usage = func() { usageReconcile(fs) }
	var host, invPath string
	var port int
	var acceptHostKey bool
	fs.StringVar(&host, "host", "", "server to check, [user@]HOST (the operator login, not a deploy account)")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.StringVar(&invPath, "inventory", "", "expected-app inventory file (JSON; names, config images, hostnames only)")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if invPath == "" {
		return fmt.Errorf("--inventory is required, e.g. --inventory expected-apps.json")
	}

	// The file is checked BEFORE the connection: a broken inventory should
	// fail fast and locally, not after asking a box for anything.
	inv, err := loadInventory(invPath)
	if err != nil {
		return err
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	// ROOT/OPERATOR ONLY, and the guard is the login rather than a password:
	// a per-app deploy account is locked to its two privileged commands, so a
	// reconcile attempted through one would fail on the far end with a message
	// about the wrong thing. Refuse it here, where the reason can be said.
	if strings.HasPrefix(tgt.user, "komizo-") {
		return fmt.Errorf("reconcile is an operator check and %q is a per-app deploy account;\n"+
			"    run it as the box's operator login (root), which is what holds the agent.", tgt.user)
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	// THE ONE READ. "report" is the only verb this command ever sends, and it
	// sends it once: the report carries every app's registration and routes,
	// and nothing else this command does touches the box at all.
	rep, err := fetchBox[box.Report](tgt, "report")
	if err != nil {
		return err
	}

	findings := reconcileInventory(inv, rep.Apps)
	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Fprintln(os.Stderr, f)
		}
		return fmt.Errorf("%d reconciliation finding(s) -- %s does not match the inventory", len(findings), tgt.host)
	}
	// Said, not silent: an inspection that prints nothing on success is
	// indistinguishable from one that never ran (komizo#47).
	note("reconciled %s: %d app(s) registered, all matching the inventory.", tgt.host, len(inv.Apps))
	return nil
}

func usageReconcile(fs *flag.FlagSet) {
	fmt.Print(`komizo reconcile - does a box hold exactly the apps it should?

  komizo reconcile --host root@server --inventory expected-apps.json

Reads the box's report ONCE and compares it with the inventory: every expected
app must be registered with the pinned config image and publish the expected
hostnames, and no other app may be registered. Any disagreement is printed and
the exit status is nonzero.

This command only ever READS. It provisions nothing, deploys nothing and
rotates no key -- run it as the operator (root), and as often as you like.

The inventory is JSON, and carries ONLY non-sensitive values -- the schema
refuses anything else, including secret- or key-looking fields:

  {"apps":[
    {"name":"blog","config":"ghcr.io/you/blog-config","hosts":["blog.example.com"]}
  ]}

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
