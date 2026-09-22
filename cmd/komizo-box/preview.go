package main

import (
	"context"
	"encoding/json"
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
		return fmt.Errorf("preview what -- up, down, ls or gc")
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
		return json.NewEncoder(os.Stdout).Encode(rec)
	case "down":
		if *app == "" || *pr == 0 {
			return fmt.Errorf("preview down needs --app and --pr")
		}
		rec, err := previewFind(cfg.Root, *app, *pr)
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
	return fmt.Errorf("preview what -- up, down, ls or gc, not %q", sub)
}

// previewFind reads one preview's record by app and PR. A preview that is not
// recorded does not exist, which is a sentence rather than a no-op: down on a
// name that is not a preview must not become a guess at what to remove.
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
	return box.PreviewRecord{}, fmt.Errorf("no preview of %s PR #%d exists", app, pr)
}
