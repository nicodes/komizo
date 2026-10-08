package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
)

// `komizo-box preview` -- the preview lifecycle, as root on the box. THE
// single implementation: the CLI's `komizo preview` runs this over SSH, and
// rootd's reaper calls the same box functions in process -- so the up a human
// runs and the down the reaper runs can never disagree about what a preview
// is. See box/preview.go for the contract this enforces.

func runPreview(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("preview what -- up, down, resolve, ls or gc")
	}
	sub, args := args[0], args[1:]

	fs := flag.NewFlagSet("preview "+sub, flag.ContinueOnError)
	app := fs.String("app", "", "the app this is a preview of")
	pr := fs.Int("pr", 0, "the pull request number")
	root := fs.String("root", "", "preview state root (default the box's)")
	routes := fs.String("routes", "/srv/_proxy/routes", "the proxy's routes directory")
	proxy := fs.String("proxy", "komizo-proxy", "the proxy container")
	network := fs.String("network", "edge", "the shared docker network")
	floors := fs.String("floors", box.DeployFloorsPath, "the capacity floors file")
	reportPath := fs.String("report", box.ReportPath, "the report the floors are checked against")
	if err := fs.Parse(args); err != nil {
		return err
	}

	run := func(ctx context.Context, stdin string, a ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "docker", a...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return string(out), nil
	}

	knob, note := box.ReadPreviewKnob(box.PreviewKnobPath)
	if note != "" {
		fmt.Fprintln(os.Stderr, "komizo-box preview:", note)
	}
	cfg := box.PreviewUpConfig{
		Knob:      knob,
		Root:      *root,
		RoutesDir: *routes,
		Proxy:     *proxy,
		Network:   *network,
	}
	ctx := context.Background()

	switch sub {
	case "resolve":
		target, err := box.ResolvePreview(knob, *app, *pr, len(fs.Args()) > 1)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(target)
	case "up":
		if *app == "" || *pr == 0 {
			return fmt.Errorf("preview up needs --app and --pr")
		}
		if b, err := os.ReadFile(*floors); err == nil {
			cfg.FloorsBody = string(b)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("cannot read %s", *floors)
		}
		cfg.ReportJSON, _ = os.ReadFile(*reportPath)
		rec, err := box.PreviewUp(ctx, run, cfg, *app, *pr, fs.Args(), time.Now())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(previewUpResponse(rec, knob))
	case "down":
		if *app == "" || *pr == 0 {
			return fmt.Errorf("preview down needs --app and --pr")
		}
		rec, err := previewFind(cfg.Root, *app, *pr)
		// ALREADY GONE IS SUCCESS. down is asked to leave nothing behind,
		// and a preview that is not recorded is that state reached. This
		// path is normal rather than exceptional: the TTL reaper removes
		// previews on its own schedule, so a pull request closed after its
		// preview expired used to fail its teardown job with
		//
		//	komizo-box: no preview of ctcalc PR #151 exists
		//
		// a red mark on every such close, for a box in exactly the state
		// the job wanted. Only the sentinel is forgiven -- a state root
		// that cannot be read is still an error.
		if errors.Is(err, errNoSuchPreview) {
			fmt.Fprintf(os.Stdout, "no preview of %s PR #%d is recorded; nothing to take down.\n", *app, *pr)
			return nil
		}
		if err != nil {
			return err
		}
		if err := box.PreviewDown(ctx, run, cfg, rec); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "preview %s is down: project, database %s and route removed.\n", rec.Project, rec.DBName)
		return nil
	case "ls":
		recs, err := box.ListPreviews(cfg.Root)
		if err != nil {
			return err
		}
		if recs == nil {
			recs = []box.PreviewRecord{}
		}
		return json.NewEncoder(os.Stdout).Encode(recs)
	case "gc":
		reap, err := box.PreviewGC(ctx, run, cfg, time.Now())
		if err != nil {
			return err
		}
		if err := box.WritePreviewReap(box.PreviewReapPath(), reap); err != nil {
			fmt.Fprintf(os.Stderr, "komizo-box preview: writing the reap record: %v\n", err)
		}
		return json.NewEncoder(os.Stdout).Encode(reap)
	}
	return fmt.Errorf("preview what -- up, down, resolve, ls or gc, not %q", sub)
}

// errNoSuchPreview is "this preview is not recorded here", as distinct from
// "the records could not be read". down treats the first as success and the
// second as the failure it is; without the distinction an unreadable state
// root would be reported as a preview that was already gone.
var errNoSuchPreview = errors.New("not a recorded preview")

// previewFind reads one preview's record by app and PR. A preview that is not
// recorded does not exist, which it says rather than guessing: down on a name
// that is not a preview must never become a guess at what to remove.
func previewFind(root, app string, pr int) (box.PreviewRecord, error) {
	recs, err := box.ListPreviews(root)
	if err != nil {
		return box.PreviewRecord{}, err
	}
	for _, r := range recs {
		if r.App == app && r.PR == pr {
			return r, nil
		}
	}
	return box.PreviewRecord{}, fmt.Errorf("%w: no preview of %s PR #%d exists", errNoSuchPreview, app, pr)
}

// Return the domain used by the privileged route writer. Deployment accounts
// cannot read the private knob directory, and must not guess a different URL.
func previewUpResponse(rec box.PreviewRecord, knob box.PreviewKnob) any {
	rec.Host = rec.WebHost(knob)
	rec.APIHost = rec.PublicAPIHost(knob)
	domain := knob.DomainFor(rec.App)
	if _, storedDomain, ok := strings.Cut(rec.Host, "."); ok {
		domain = storedDomain
	}
	return struct {
		box.PreviewRecord
		Domain string `json:"domain"`
	}{rec, domain}
}
