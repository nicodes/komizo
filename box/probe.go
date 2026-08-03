package box

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Probe reads a machine.
//
// A struct with two seams rather than a package of free functions, and both
// seams exist for the tests. Root prefixes every filesystem path, so a test
// builds a fake /proc and /var/lib/komizo in a temp directory. Docker runs
// docker, so a test hands back canned output instead of needing a daemon.
//
// The zero value probes the real machine, which is what komizo-box uses.
type Probe struct {
	// Root is prefixed to every absolute path this reads. Empty in production.
	Root string
	// Docker runs a docker command and returns its stdout. Nil means the real
	// one. A docker that is absent or not running is not an error here -- it is
	// the "bare" and "docker-stopped" server states, which are things to show.
	Docker func(ctx context.Context, args ...string) (string, error)
	// Now is the clock, for tests that need a fixed report time.
	Now func() time.Time
	// Agent is the version of the binary doing the probing, reported so the
	// interface can say a box is running an old one.
	Agent string
}

func (p *Probe) path(abs string) string {
	if p.Root == "" {
		return abs
	}
	return filepath.Join(p.Root, abs)
}

func (p *Probe) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// docker runs one docker command.
//
// Errors are swallowed by every caller on purpose. This whole package describes
// a box that may be half set up, and a docker call that fails is usually the
// answer -- no daemon, no such container, a network that does not exist -- not
// a reason to abandon the report and show nothing at all.
func (p *Probe) docker(ctx context.Context, args ...string) (string, error) {
	if p.Docker != nil {
		return p.Docker(ctx, args...)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.Output()
	return string(out), err
}

// dockerOK reports whether there is a daemon to talk to.
func (p *Probe) dockerOK(ctx context.Context) bool {
	_, err := p.docker(ctx, "info", "--format", "{{.ServerVersion}}")
	return err == nil
}

// Report produces one complete reading.
//
// Two docker calls, whatever is on the box. Everything below reads the index
// they produce -- see docker.go, where that is the property being defended.
func (p *Probe) Report(ctx context.Context) Report {
	r := Report{V: Version, At: p.now(), Apps: []App{}, Problems: []Problem{}}
	r.Server = p.server(ctx)

	// Everything below assumes docker. An uninitialised box reports its state
	// and stops -- there is nothing else true to say about it.
	if !r.Server.Ready() {
		return r
	}

	inv := p.dockerInventory(ctx)
	r.Apps = p.apps(inv)
	r.Proxy = p.proxy(inv)
	r.Network = p.network(ctx, r.Proxy, inv)
	r.Orphans = p.orphans()
	r.System = p.System(inv)
	r.Problems = Diagnose(r)
	return r
}

// server is the box itself.
func (p *Probe) server(ctx context.Context) Server {
	s := Server{State: "bare"}
	if v, err := p.docker(ctx, "--version"); err == nil {
		if p.dockerOK(ctx) {
			s.State = "ready"
			s.Docker = strings.TrimSpace(strings.SplitN(v, "\n", 2)[0])
		} else {
			s.State = "docker-stopped"
		}
	}

	// The distribution as it names itself.
	for _, ln := range readLines(p.path(OSRelease)) {
		if v, ok := strings.CutPrefix(ln, "PRETTY_NAME="); ok {
			s.OS = strings.Trim(strings.TrimSpace(v), `"`)
			break
		}
	}

	s.UptimeS = p.uptime()
	s.Komizo = p.komizoInstall()
	if s.State == "ready" {
		s.HostKeys = p.hostKeys()
	}
	return s
}

// komizoInstall reads back the stamp komizo wrote, rather than assuming it.
func (p *Probe) komizoInstall() KomizoInstall {
	k := KomizoInstall{Agent: p.Agent}
	lines := readLines(p.path(VersionPath))
	if len(lines) == 0 {
		return k
	}
	k.Installed = true
	// Two lines, always: the komizo version that provisioned the box, then the
	// content stamp of what it wrote. Anything else is a file komizo did not
	// write, and reading one field out of it would be a guess presented as a
	// fact -- so the file's existence is reported and nothing else is claimed.
	if len(lines) < 2 {
		return k
	}
	version, stamp := strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
	if version == "" || stamp == "" {
		return k
	}
	k.Version, k.Stamp = version, stamp
	return k
}

// hostKeys are the server's own public keys, for the known_hosts CI pins.
func (p *Probe) hostKeys() []HostKey {
	paths, _ := filepath.Glob(p.path("/etc/ssh/ssh_host_*_key.pub"))
	sort.Strings(paths)
	var out []HostKey
	for _, f := range paths {
		for _, ln := range readLines(f) {
			fields := strings.Fields(ln)
			if len(fields) < 2 {
				continue
			}
			if strings.HasPrefix(fields[0], "ssh-") || strings.HasPrefix(fields[0], "ecdsa-") {
				out = append(out, HostKey{Type: fields[0], Key: fields[1]})
			}
		}
	}
	return out
}

// apps walks komizo's own records and joins each to what docker says.
func (p *Probe) apps(inv dockerInventory) []App {
	states := p.appStates()
	out := make([]App, 0, len(states))
	for _, as := range states {
		a := App{
			Name:        as.name,
			User:        as.st["CI_USER"],
			Dir:         as.dir(),
			ConfigImage: as.st["CONFIG_IMAGE"],
			KnownAs:     splitList(as.st["KNOWN_AS"]),
			Version:     "none",
		}
		if a.User == "" {
			a.User = "?"
		}
		// STOPPED lives beside the app's own record so the deploy path can read
		// it without asking anything off the box.
		if as.st["STOPPED"] == "1" {
			a.Stopped = true
			a.StoppedBy = as.st["STOPPED_BY"]
			if t, err := time.Parse(time.RFC3339, as.st["STOPPED_AT"]); err == nil {
				a.StoppedAt = t
			}
		}
		if a.Dir != "" {
			if v := readValue(p.path(filepath.Join(a.Dir, ".env")), "APP_VERSION"); v != "" {
				a.Version = v
			}
			a.Hosts = p.hosts(a.Dir)
			a.Containers = p.containers(a.Dir, inv)
		}
		out = append(out, a)
	}
	return out
}

// hosts is what the app declared it answers on.
//
// Read from the app's own hostnames file rather than from the caddy fragment
// beside it. The fragment is GENERATED from this, so parsing it back would be
// reading komizo's own output to learn what the app said: the same answer, one
// transformation later, and wrong the moment the generator changes.
func (p *Probe) hosts(dir string) []Host {
	var out []Host
	for _, ln := range readLines(p.path(filepath.Join(dir, "hostnames"))) {
		if i := strings.IndexByte(ln, '#'); i >= 0 {
			ln = ln[:i]
		}
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		h := Host{Name: f[0]}
		if len(f) >= 3 && f[1] == "->" {
			h.Service = f[2]
		}
		out = append(out, h)
	}
	return out
}

// orphans are directories under /srv with no state file behind them.
//
// Names starting with "_" are komizo's own and are skipped: they never have
// one, so they would otherwise always look orphaned.
func (p *Probe) orphans() []string {
	ents, err := os.ReadDir(p.path(SrvDir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		if _, err := os.Stat(p.path(filepath.Join(AppsDir, e.Name()+".env"))); err != nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// sortBy orders a slice by a string key.
//
// Every list in a report goes through this. A report of the same box twice must
// be the same document -- map iteration is not, and a report that reshuffles
// itself every minute is one nothing can usefully diff or alert on.
func sortBy[T any](s []T, key func(T) string) {
	sort.Slice(s, func(i, j int) bool { return key(s[i]) < key(s[j]) })
}

// splitList reads a comma or space separated field into a slice, dropping
// blanks.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
