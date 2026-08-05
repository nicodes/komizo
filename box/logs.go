package box

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// What an app has been saying, put where the account that serves this box can
// read it.
//
// komizo-be design/app-only.md §5. The interface runs `docker logs` as root over
// SSH; the app cannot, and the account that serves the box has NO DOCKER GROUP
// deliberately -- docker socket access is root on the box, so granting it would
// delete that account's whole argument in one line.
//
// Nor can the files simply be handed over. json-file logs live at
// /var/lib/docker/containers/<id>/<id>-json.log, 0600 inside a 0700 root:root
// directory, and docker recreates both on every container recreate -- so a group
// or an ACL granted to them is undone by the next deploy.
//
// So ROOT TAILS AND WRITES HERE, which is the shape this box already uses in the
// other direction for results. rootd has docker; one `docker compose logs` per
// app on a timer is a file the serving account can open, and it works whatever
// logging driver an app is using.
//
// TAIL, NOT INDEX. §5: "Streaming recent output is a route on a proxy that is
// already running. Search my logs from last Tuesday is a different product with
// a storage bill, and registry.md §1's test -- could the box answer this about
// itself -- says the answer lives on the box or nowhere."

// LogsDir holds one file per app, plus the shared proxy's.
//
// Under ServedDir, which is root-writes-agent-reads and setgid, so a file root
// puts here is born in a group the serving account can open.
const LogsDir = ServedDir + "/logs"

// LogsMax bounds one app's file.
//
// A quarter of a megabyte is a few thousand lines, which is far more than the
// tail anybody reads and small enough that a box running twenty apps spends five
// megabytes on this. Bounded at all because it is written every interval
// forever, on a disk that is somebody else's.
const LogsMax = 256 << 10

// The proxy is not served here. See cmd/komizo-box/collect.go: Caddy's error
// logger writes full requests -- client IP, URI, query string -- to stdout, so
// collecting it would put them in a file the internet-facing account reads.

// LogPath is where one subject's log lives, and it refuses a name that is not
// one.
//
// Checked rather than trusted: this is joined into a path, and the name arrives
// from a query string on a route reachable through the box's proxy.
// errNotAnApp is a name this will not file, which is a bad request rather than
// a thing that is missing.
var errNotAnApp = errors.New("not an app")

func LogPath(dir, name string) (string, error) {
	if name == "" || len(name) > 100 || strings.ContainsAny(name, "/.") {
		return "", fmt.Errorf("%w: %q", errNotAnApp, name)
	}
	if strings.HasPrefix(name, "_") {
		// komizo's own namespace, which validateApp refuses for apps and which
		// holds no logs this serves. The proxy lives in here and is deliberately
		// not collected -- see collect.go.
		return "", fmt.Errorf("%w: %q", errNotAnApp, name)
	}
	return filepath.Join(dir, name+".log"), nil
}

// WriteLog replaces one subject's log, atomically and bounded.
//
// Replaced whole rather than appended, because this is a TAIL: what it holds is
// the last of what docker has, and docker is already the thing keeping history.
// Appending would make this a second copy of a log that rotates underneath it.
//
// Atomically, because the serving account reads on its own schedule and the two
// are not coordinated -- a reader that caught a half-written file would show
// somebody a truncated last line and call it their app's output.
func WriteLog(dir, name string, body []byte) error {
	path, err := LogPath(dir, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if len(body) > LogsMax {
		// Trimmed from the FRONT: the end is the recent part, which is the part
		// anybody opening a log wants. Cut at a line boundary so the first line
		// shown is a line rather than the tail of one.
		body = body[len(body)-LogsMax:]
		if i := bytes.IndexByte(body, '\n'); i >= 0 && i+1 < len(body) {
			body = body[i+1:]
		}
	}
	// UNCHANGED IS NOT WRITTEN. This runs four times a minute per app, forever,
	// and writeFileAtomic rewrites and fsyncs the whole file -- so an idle app
	// was costing hundreds of megabytes of writes a day to store bytes that were
	// already there, on a disk this file itself calls "somebody else's".
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, body) {
		return nil
	}
	// 0640: root writes, the serving account reads, and nothing else on the box
	// does. Log lines are the most sensitive bytes this machine produces.
	return writeFileAtomic(path, body, 0o640)
}

// ReadLog returns the last n lines of what was written.
//
// The bound is applied HERE as well as by whoever wrote the file, because the
// caller asks for a tail and the file holds whatever the last interval produced.
func ReadLog(dir, name string, n int) (string, error) {
	path, err := LogPath(dir, name)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}

// PruneLogs removes the files of apps that are no longer here.
//
// An app that was removed leaves its log behind otherwise, and a log for
// something that does not exist is a thing somebody can open and be confused by
// -- as well as bytes nobody will ever collect.
func PruneLogs(dir string, keep []string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	live := map[string]bool{}
	for _, k := range keep {
		live[k+".log"] = true
	}
	for _, e := range ents {
		// ONLY WHAT THIS WRITES. --logs is an operator flag, and pointed one
		// directory up it would otherwise delete history.jsonl every fifteen
		// seconds, silently.
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") || live[e.Name()] {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return nil
}

// LogsResponse is one subject's recent output.
type LogsResponse struct {
	V     int    `json:"v"`
	App   string `json:"app"`
	Lines string `json:"lines"`
}

func (l LogsResponse) Schema() int { return l.V }

// logTailMax bounds what one request may ask for.
//
// The same reasoning as the box's own log command: this is a tail, and an
// unbounded one is a different product.
const logTailMax = 2000

// serveLog hands over what rootd collected, to a device this box takes orders
// from.
//
// A POST, and not because it changes anything -- it changes nothing. It carries
// a SIGNED ENVELOPE, which is what app-only.md §5 requires of logs and what a
// GET has nowhere to put. The token that came with it still gates the door;
// this gates who may look.
//
// THE ID IS NOT CONSUMED, and that is a decision rather than an omission. §4's
// replay record exists so a command is not APPLIED twice; reading a log twice is
// reading a log twice. Spending an envelope here would also mean a read could
// deny a later one by using up its id, and would put a write on the path of
// every log view. What bounds a captured envelope instead is its expiry, which
// is minutes -- and a caller who has one also needs the read token that came
// with it.
func serveLog(cfg APIConfig, w http.ResponseWriter, r *http.Request) {
	if cfg.LogsDir == "" {
		http.Error(w, "this box is not collecting logs", http.StatusServiceUnavailable)
		return
	}
	if len(cfg.OperatorKeys) == 0 {
		// Nobody may read these, because nobody has been given the means to ask.
		// Said plainly rather than answered with an empty log.
		http.Error(w, "this box takes orders from nobody", http.StatusConflict)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxCommandBytes+1))
	if err != nil {
		http.Error(w, "could not read that request", http.StatusBadRequest)
		return
	}
	if len(raw) > MaxCommandBytes {
		http.Error(w, "that request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	c, _, err := VerifyCommand(cfg.OperatorKeys, raw, cfg.ServerID, cfg.Now())
	switch {
	case err != nil && !errors.Is(err, ErrCommandRefused):
		// A version this box does not speak. The signature already verified, so
		// the caller is a device this box trusts and §4 says it is entitled to a
		// sentence rather than a silence -- the same split the command route
		// makes.
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	case err != nil || c.Op != OpLogsRead:
		// One answer for every reason, the same as everywhere else here: which
		// of them it was is not this caller's business.
		http.Error(w, "this box will not answer that", http.StatusForbidden)
		return
	}

	// ONE RULE for an app name. This read c.Args["app"] directly, so "-x", "a b"
	// and "wéb" were answered as ordinary apps here while AppOf refused all
	// three for every other op -- two rules for one signed field, which is one
	// rule that stops matching.
	name, err := c.AppOf()
	if err != nil {
		http.Error(w, "that is not an app", http.StatusBadRequest)
		return
	}
	tail := 200
	if v := c.Args["tail"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > logTailMax {
			http.Error(w, "tail must be a number between 1 and 2000", http.StatusBadRequest)
			return
		}
		tail = n
	}

	lines, err := ReadLog(cfg.LogsDir, name, tail)
	switch {
	case errors.Is(err, errNotAnApp):
		// A name this box will not file. A bad request rather than a missing
		// thing, and telling them apart is the point -- see below.
		http.Error(w, "that is not an app", http.StatusBadRequest)
		return
	case errors.Is(err, fs.ErrNotExist):
		// Absent is not an error about the caller: an app that has never started
		// has nothing to say, and one collected a moment from now will.
		http.Error(w, "nothing collected for that app yet", http.StatusNotFound)
		return
	case err != nil:
		// UNREADABLE IS NOT ABSENT. Collapsing the two is the bug paths.go
		// records as having shipped: ReadSamples treated an unreadable file as
		// an empty one, so /v1/history said "no readings" on every box forever
		// and nothing anywhere mentioned permission.
		fmt.Fprintf(os.Stderr, "komizo-box: could not read %s's log: %v\n", name, err)
		http.Error(w, "this box could not read that log", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, LogsResponse{V: APIVersion, App: name, Lines: lines})
}
