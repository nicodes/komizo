package main

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
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
	names, ok := appNames(root, dir)
	for _, name := range names {
		sub, err := resolveSubject(root, name, false)
		if err != nil {
			continue
		}
		write(ctx, dir, name, sub)
	}
	// THE SHARED PROXY IS NOT COLLECTED, and this is the correction that matters
	// most on this path.
	//
	// It looked safe by reading: alpine-proxy.sh sends ACCESS logging to a file
	// rather than to stdout, deliberately, "so that the proxy's own log -- the
	// one that explains a certificate failure -- does not become a request
	// firehose". That is true and it is not the whole log.
	//
	// Caddy's ERROR logger is a separate sink and it goes to stdout, carrying a
	// full request: remote_ip, client_ip, the URI with its query string, and the
	// User-Agent. Every 502, every upstream timeout, every handshake failure --
	// and on the error path that stdout line is the ONLY place the request
	// appears at all. Found by running it, not by reading it.
	//
	// So collecting it would copy client IPs and request paths into a file the
	// internet-facing account reads and serves, which is precisely what
	// access.go's "COUNTS, NEVER LINES" and the 0750 on the access log directory
	// exist to prevent. The file-not-stdout decision would have been undone by
	// collecting the stdout instead.
	//
	// `komizo logs --proxy` over SSH stays, and is what §5 actually justified: a
	// root command an operator runs is not a file an internet-facing process
	// hands out. Serving it here needs filtering that makes a promise about
	// Caddy's log shape, and that is a decision on its own rather than a line
	// slipped into a collector.

	// An app that was removed leaves its log behind otherwise -- but ONLY when
	// the enumeration worked. A directory that could not be read looks exactly
	// like a box with no apps, and pruning against that would delete every log
	// on the machine.
	if ok {
		_ = box.PruneLogs(dir, names)
	}
}

func write(ctx context.Context, dir, name string, sub subject) {
	// BOUNDED IN BYTES, not just in lines. --tail bounds how many lines docker
	// returns and says nothing about how long one is, and the capture ran
	// unbounded at root on a fifteen-second timer -- so a single very long line
	// was an allocation the size of that line, over and over. LogsMax is applied
	// after, which was too late to be the bound.
	out, err := composeCapped(ctx, sub.dir, sub.project, box.LogsMax,
		"logs", "--tail", strconv.Itoa(collectTail), "--no-color")
	_ = err
	if strings.TrimSpace(out) == "" {
		// NOTHING TO SAY IS NOT THE SAME AS SAYING NOTHING.
		//
		// This used to fire only when compose FAILED -- and compose on a project
		// with no containers exits 0 with empty output, which is exactly what an
		// app mid-deploy and an app that just crashed and was recreated both
		// look like. So the two moments somebody is most likely to be watching
		// were the two that wiped the last thing the app said.
		return
	}
	// WHICH SERVICE SAID WHAT, recorded rather than inferred.
	//
	// nicodes/komizo-be#165. compose prefixes each line with the CONTAINER
	// name, and the prefix format varies by compose version -- 5.0.0 writes
	// "gate-1  |" where 5.1.4 writes "web-gate-1  |" for the same stack. So this
	// asks compose which container is which service and stores the answer.
	//
	// ONE EXTRA CALL PER APP PER INTERVAL, and it is worth being explicit about
	// the cost: `ps` stats the project, where `logs` reads files. If it fails,
	// the lines are stored WITHOUT a service rather than not stored -- a log
	// nobody can filter is still a log, and losing it because a second command
	// failed would be trading the whole feature for part of one.
	_ = box.WriteLog(dir, name, []byte(withServices(ctx, sub, out)))
}

// withServices rewrites compose's container-prefixed output into komizo's form.
func withServices(ctx context.Context, sub subject, out string) string {
	byContainer := serviceOf(ctx, sub)
	lines := make([]box.LogLine, 0, 64)
	for _, ln := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if ln == "" {
			continue
		}
		name, text, ok := cutComposePrefix(ln)
		if !ok {
			// compose writes un-prefixed lines too -- its own "Attaching to
			// ..." among them. Kept, with no service, rather than dropped:
			// deciding which of compose's own lines are worth keeping is a
			// judgement this has no basis for making.
			lines = append(lines, box.LogLine{Text: ln})
			continue
		}
		lines = append(lines, box.LogLine{Service: byContainer[name], Text: text})
	}
	return box.FormatLog(lines)
}

// cutComposePrefix splits "container-name  | message" at the pipe.
//
// The container name is only used to look up a service, so a prefix this does
// not recognise costs the service and keeps the line. It must NOT be used to
// derive the service itself -- that is the guess komizo-be#165 exists to remove.
func cutComposePrefix(ln string) (name, text string, ok bool) {
	i := strings.Index(ln, "|")
	if i < 0 {
		return "", "", false
	}
	name = strings.TrimSpace(ln[:i])
	if name == "" || strings.ContainsAny(name, " \t") {
		// A pipe inside a message rather than compose's separator. A container
		// name has no spaces, so one before the first pipe means this line was
		// never prefixed.
		return "", "", false
	}
	text = ln[i+1:]
	if len(text) > 0 && text[0] == ' ' {
		text = text[1:]
	}
	return name, text, true
}

// serviceOf maps each of a project's containers to the service it runs.
//
// ASKED, NEVER DERIVED. The alternative is stripping the project prefix and a
// replica suffix off the container name, which cannot tell an app whose service
// is called "web-1" from replica 1 of "web" -- and which depends on a naming
// scheme compose has already changed once.
//
// An empty map is a valid answer: the lines are then stored with no service,
// which is what a reader is told rather than what it has to infer.
func serviceOf(ctx context.Context, sub subject) map[string]string {
	out, err := composeOut(ctx, sub.dir, sub.project, "ps", "--all", "--format", "json")
	if err != nil {
		return nil
	}
	byContainer := map[string]string{}
	// ONE JSON DOCUMENT PER LINE, not an array. compose has emitted both across
	// versions -- and a decoder in a loop reads either, because a stream of one
	// array is just one document.
	dec := json.NewDecoder(strings.NewReader(out))
	for {
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			break
		}
		var rows []struct {
			Name    string `json:"Name"`
			Service string `json:"Service"`
		}
		if err := json.Unmarshal(v, &rows); err != nil {
			var one struct {
				Name    string `json:"Name"`
				Service string `json:"Service"`
			}
			if json.Unmarshal(v, &one) != nil {
				continue
			}
			rows = append(rows, one)
		}
		for _, r := range rows {
			if r.Name != "" && r.Service != "" {
				byContainer[r.Name] = r.Service
			}
		}
	}
	return byContainer
}

// appNames is every app komizo has a record of, by name.
//
// From komizo's own records rather than by globbing /srv, for the reason
// paths.go gives: an app placed elsewhere with --app-dir is invisible to a glob,
// so its logs would be permanently empty.
func appNames(root, dir string) ([]string, bool) {
	ents, err := os.ReadDir(root + box.AppsDir)
	if err != nil {
		// Told apart from "no apps", because the caller prunes against this.
		return nil, false
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
	return out, true
}

func cutSuffix(s, suffix string) (string, bool) {
	if len(s) <= len(suffix) || s[len(s)-len(suffix):] != suffix {
		return "", false
	}
	return s[:len(s)-len(suffix)], true
}
