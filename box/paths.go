package box

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Where komizo keeps things on a server.
//
// Constants rather than values threaded through every call: these are decided
// by the provisioning scripts, not by a caller, and a path passed as an
// argument is a path some future caller can pass wrongly. The tests that need
// to point somewhere else take a root prefix instead -- see probe.Root.
const (
	StateDir = "/var/lib/komizo"
	AppsDir  = StateDir + "/apps"

	// RunDir is the one directory anything unprivileged may enter, and
	// ReportPath is the one file in it.
	//
	// NOT under StateDir, which is 0750 root:root because apps/<app>.env names
	// every app's deploy account and directory. A world-readable file inside a
	// directory nothing may traverse is world-readable in name only -- which is
	// what this was, and the mode on the file said otherwise.
	//
	// /run because that is what /run is for: state describing the system since
	// it was booted. It is tmpfs, so a reboot clears it and the report is
	// rewritten on rootd's first tick seconds later. That is the RIGHT
	// behaviour rather than a cost: a report is a claim about now, and one that
	// outlives the boot it describes is a lie waiting to be read.
	RunDir     = "/run/komizo"
	ReportPath = RunDir + "/report.json"
	// HistoryPath is one JSON reading per line, oldest first.
	//
	// Append-only and trimmed by bytes. Reading it is a tail, because the
	// question is always about recent minutes.
	//
	// Under StateDir, and so root-only, for two reasons. It has to SURVIVE a
	// reboot, which is the opposite of the report; and nothing unprivileged
	// needs it -- the agent posts each report as it is written and the service
	// accumulates the history at its end.
	HistoryPath = StateDir + "/history.jsonl"
	VersionPath = StateDir + "/version"

	// APISocketDir holds the socket the box answers on, and it is its OWN
	// directory for two reasons that arrived a day apart.
	//
	// The first is that RunDir is 0755 root:root, so the account that opens the
	// socket cannot create a file in it. That is the fourth time this shape has
	// bitten -- the report, the state directory, the credential, and now this --
	// and every time it was a process that could READ where it needed to WRITE.
	//
	// The second is what comes next: the box's proxy has to reach this socket,
	// which means a bind mount, and mounting RunDir would hand the one
	// internet-facing container on the box a writable path next to report.json.
	// A directory with nothing in it but a socket is the smaller thing to lend.
	APISocketDir = RunDir + "/api"

	// APISocketPath is where the box answers for itself.
	//
	// A socket rather than a port, so nothing new listens on the network -- see
	// cmd/komizo-box/serve.go.
	APISocketPath = APISocketDir + "/api.sock"
	// PendingDir is where signed requests land for rootd to apply. Nothing in v0
	// writes here; the directory is created so the shape is visible on a box and
	// the permissions are decided once, by the thing that owns them.
	PendingDir = StateDir + "/pending"

	SrvDir    = "/srv"
	ProxyDir  = SrvDir + "/_proxy"
	AccessLog = ProxyDir + "/logs/access.log"
	Caddyfile = ProxyDir + "/Caddyfile"

	OSRelease = "/etc/os-release"
)

// state is one app's record, as key=value lines under AppsDir.
//
// Read with a plain scanner rather than parsed as shell. These files are
// written by komizo and read by komizo, and treating them as shell would mean
// the difference between a value and a command depends on what an app was
// named.
type state map[string]string

func readState(path string) (state, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st := state{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		// First wins. A file with the same key twice is malformed, and taking
		// the first is what the deploy script does when it reads the same file
		// -- so the box and the report agree about which value is live.
		if _, dup := st[k]; !dup {
			st[k] = v
		}
	}
	return st, sc.Err()
}

// appStates is every app on the box, by name, in a stable order.
//
// Enumerated from komizo's own records rather than by globbing /srv, and the
// app NAME comes from the file name rather than the directory it points at. An
// app placed elsewhere with --app-dir is invisible to a glob, so its charts are
// permanently empty; an app whose directory does not match its name is
// attributed to a bucket no row matches, which looks identical.
func (p *Probe) appStates() []appState {
	ents, err := os.ReadDir(p.path(AppsDir))
	if err != nil {
		return nil
	}
	var out []appState
	for _, e := range ents {
		name := strings.TrimSuffix(e.Name(), ".env")
		if name == e.Name() || e.IsDir() {
			continue
		}
		st, err := readState(filepath.Join(p.path(AppsDir), e.Name()))
		if err != nil {
			continue
		}
		out = append(out, appState{name: name, st: st})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

type appState struct {
	name string
	st   state
}

func (a appState) dir() string { return a.st["APP_DIR"] }

// readLines reads a file and splits it, returning nothing when it is absent.
// Absence is the common case for most of these -- an app with no hostnames, a
// box with no proxy -- and is not an error worth propagating.
func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

// readValue pulls one KEY=value out of a file, the first match only.
func readValue(path, key string) string {
	for _, ln := range readLines(path) {
		if v, ok := strings.CutPrefix(ln, key+"="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
