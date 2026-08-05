package box

import (
	"bytes"
	"fmt"
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

// ProxyLogName is what the shared proxy's log is filed under.
//
// Underscore-prefixed, which is the one namespace an app cannot have -- komizo
// reserves it, and validateApp refuses it -- so this can never collide with an
// app's file.
const ProxyLogName = "_proxy"

// LogPath is where one subject's log lives, and it refuses a name that is not
// one.
//
// Checked rather than trusted: this is joined into a path, and the name arrives
// from a query string on a route reachable through the box's proxy.
func LogPath(dir, name string) (string, error) {
	if name == "" || len(name) > 100 || strings.ContainsAny(name, "/.") {
		return "", fmt.Errorf("%q is not an app", name)
	}
	if name != ProxyLogName && strings.HasPrefix(name, "_") {
		// The rest of the underscore namespace is komizo's own and holds no
		// logs, so asking for one is asking about something that is not there.
		return "", fmt.Errorf("%q is not an app", name)
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
	live := map[string]bool{ProxyLogName + ".log": true}
	for _, k := range keep {
		live[k+".log"] = true
	}
	for _, e := range ents {
		if e.IsDir() || live[e.Name()] {
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

// serveLog hands over what rootd collected.
func serveLog(cfg APIConfig, w http.ResponseWriter, r *http.Request) {
	if cfg.LogsDir == "" {
		http.Error(w, "this box is not collecting logs", http.StatusServiceUnavailable)
		return
	}
	name := r.URL.Query().Get("app")
	if name == "" {
		http.Error(w, "which app?", http.StatusBadRequest)
		return
	}
	tail := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > logTailMax {
			http.Error(w, "tail must be a number between 1 and 2000", http.StatusBadRequest)
			return
		}
		tail = n
	}
	lines, err := ReadLog(cfg.LogsDir, name, tail)
	if err != nil {
		// Absent is not an error about the caller: an app that has never started
		// has nothing to say, and one collected a moment from now will.
		http.Error(w, "nothing collected for that app yet", http.StatusNotFound)
		return
	}
	writeJSON(w, LogsResponse{V: APIVersion, App: name, Lines: lines})
}
