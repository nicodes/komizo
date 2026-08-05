package main

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/nicodes/komizo/box"
)

// rootd, collecting what each app has been saying.
//
// komizo-be design/app-only.md §5. The account that serves this box has no
// docker group -- deliberately, because docker socket access is root on the box
// -- and docker's own log files are 0600 inside a 0700 directory it recreates on
// every deploy, so no group or ACL survives. Root is the only thing that can
// read them, so root reads them and writes the result somewhere the serving
// account can.
//
// `docker compose logs` rather than the files, because it works whatever logging
// driver an app is using and needs no knowledge of where docker put anything.

// collectEvery is how often each app's tail is refreshed.
//
// Not the report's minute: a log somebody opens is worth having fresher than
// that. Not the command timer's half-second either -- this runs a docker command
// per app, where that one stats a directory.
const collectEvery = 15 * time.Second

// collectTail is how many lines are kept per app.
//
// More than anybody reads at once, so the route can serve a smaller tail out of
// it without going back to docker for every request.
const collectTail = 500

// collectLogs refreshes every app's log once.
//
// Errors are not returned: one app whose compose file is broken is not a reason
// to stop collecting for the others, and rootd's job is to keep running.
func collectLogs(ctx context.Context, root, dir string) {
	names := appNames(root, dir)
	for _, name := range names {
		sub, err := resolveSubject(root, name, false)
		if err != nil {
			continue
		}
		write(ctx, dir, name, sub)
	}
	// The shared proxy, which is where Caddy records its certificate work -- the
	// only place a TLS failure is explained, and the thing tui_server.go says is
	// worth having on its own.
	//
	// AND IT IS NOT THE ACCESS LOG, which is the question this raises and the
	// reason it is answered here. alpine-proxy.sh sends access logging to a file
	// rather than to stdout, in its own words, "so that the proxy's own log --
	// the one that explains a certificate failure -- does not become a request
	// firehose". That file is 0750 root:root because "they carry client IPs and
	// request paths, which is the one thing on this box that is about the people
	// using it rather than about the box", and nothing here reads it.
	//
	// So what is collected is Caddy's operational log and only that. If anybody
	// ever points access logging at stdout, this line starts copying client IPs
	// into a file an internet-facing process can read, and box/access.go's
	// standing promise -- "COUNTS, NEVER LINES" -- stops being true of this box.
	write(ctx, dir, box.ProxyLogName, subject{dir: box.ProxyDir, project: ProxyProject})

	// An app that was removed leaves its log behind otherwise.
	_ = box.PruneLogs(dir, names)
}

func write(ctx context.Context, dir, name string, sub subject) {
	out, err := composeOut(ctx, sub.dir, sub.project,
		"logs", "--tail", strconv.Itoa(collectTail), "--no-color")
	if err != nil && out == "" {
		// Nothing running, or no compose file. Not an error worth recording: an
		// app that has never started has nothing to say, and writing an empty
		// file over a previous tail would throw away the last thing it said.
		return
	}
	_ = box.WriteLog(dir, name, []byte(out))
}

// appNames is every app komizo has a record of, by name.
//
// From komizo's own records rather than by globbing /srv, for the reason
// paths.go gives: an app placed elsewhere with --app-dir is invisible to a glob,
// so its logs would be permanently empty.
func appNames(root, dir string) []string {
	ents, err := os.ReadDir(root + box.AppsDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name, ok := cutSuffix(e.Name(), ".env")
		if !ok {
			continue
		}
		// Named as something that can be filed. A record whose name cannot be
		// is one nothing could serve anyway.
		if _, err := box.LogPath(dir, name); err != nil {
			continue
		}
		out = append(out, name)
	}
	return out
}

func cutSuffix(s, suffix string) (string, bool) {
	if len(s) <= len(suffix) || s[len(s)-len(suffix):] != suffix {
		return "", false
	}
	return s[:len(s)-len(suffix)], true
}
