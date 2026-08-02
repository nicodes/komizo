package box

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Everything docker is asked, asked once.
//
// `docker ps` and `docker inspect` are the slow part of describing a box, and
// the cost is per CALL rather than per container -- so both are read for the
// whole machine and then indexed. The shell this replaces learned the same
// lesson the hard way and says so: a box with six apps of five containers was
// running several hundred processes every five seconds for a page that is
// usually just left open.

// dockerInventory is every container on the box, indexed by id.
type dockerInventory struct {
	byID map[string]*containerInfo
}

type containerInfo struct {
	id      string
	name    string
	state   string
	status  string
	service string
	image   string

	startedAt  time.Time
	finishedAt time.Time
	exitCode   int
	pid        int
}

// The separator between the fields of one record. Docker's --format writes
// whatever is asked for, and a container name or an image reference can contain
// almost anything -- but not a tab, and not a newline.
const dsep = "\t"

func (p *Probe) dockerInventory(ctx context.Context) dockerInventory {
	inv := dockerInventory{byID: map[string]*containerInfo{}}

	// .State is the machine-readable word (running, exited); .Status is docker's
	// own prose (Up 3 hours), which is what a person actually wants to read.
	out, err := p.docker(ctx, "ps", "-a", "--no-trunc", "--format",
		strings.Join([]string{
			"{{.ID}}", "{{.Names}}", "{{.State}}", "{{.Status}}",
			`{{.Label "com.docker.compose.service"}}`, "{{.Image}}",
		}, dsep))
	if err != nil {
		return inv
	}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), dsep)
		if len(f) < 6 || f[0] == "" {
			continue
		}
		inv.byID[f[0]] = &containerInfo{
			id: f[0], name: f[1], state: f[2], status: f[3], service: f[4], image: f[5],
		}
	}
	if len(inv.byID) == 0 {
		return inv
	}

	// When each container last started and last stopped, and why -- as
	// timestamps and a number rather than docker's prose. From inspect rather
	// than ps, because ps offers only .RunningFor (prose) and .CreatedAt
	// (creation, which a restart does not move).
	ids := make([]string, 0, len(inv.byID))
	for id := range inv.byID {
		ids = append(ids, id)
	}
	args := append([]string{"inspect", "--format",
		strings.Join([]string{
			"{{.Id}}", "{{.State.StartedAt}}", "{{.State.FinishedAt}}",
			"{{.State.ExitCode}}", "{{.State.Pid}}",
		}, dsep)}, ids...)
	out, err = p.docker(ctx, args...)
	if err != nil {
		return inv
	}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), dsep)
		if len(f) < 5 {
			continue
		}
		c, ok := inv.byID[f[0]]
		if !ok {
			continue
		}
		c.startedAt = parseStamp(f[1])
		c.finishedAt = parseStamp(f[2])
		c.exitCode, _ = strconv.Atoi(f[3])
		c.pid, _ = strconv.Atoi(f[4])
	}
	return inv
}

// parseStamp reads one of docker's RFC3339 times.
//
// Docker reports a zero time for a container that has never run or has never
// stopped, and that parses perfectly well -- it would simply read as an uptime
// measured from the year 1.
func parseStamp(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil || t.Year() <= 1 {
		return time.Time{}
	}
	return t
}

// composeIDs is the container ids belonging to one app.
//
// Membership comes from compose rather than from a label match on the project
// name: compose derives that name from the directory and normalises it, so an
// app under a custom --app-dir would not match its own containers.
//
// Asked with -a so a container that exited is listed as exited instead of
// vanishing -- a stack that died is exactly what you are looking for here, and
// an absent row reads as "no such service".
func (p *Probe) composeIDs(ctx context.Context, dir string, all bool) []string {
	compose := p.path(filepath.Join(dir, "compose.yml"))
	if !fileExists(compose) {
		return nil
	}
	args := []string{"compose", "-f", compose, "--project-directory", p.path(dir), "ps"}
	if all {
		args = append(args, "-a")
	}
	args = append(args, "-q")
	out, err := p.docker(ctx, args...)
	if err != nil {
		return nil
	}
	var ids []string
	for _, ln := range strings.Split(out, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			ids = append(ids, ln)
		}
	}
	return ids
}

// containers is one app's containers, named individually rather than counted.
//
// A count says three are up; it cannot say WHICH of four is missing, and the
// missing one is the whole question when something 502s.
func (p *Probe) containers(ctx context.Context, dir string, inv dockerInventory) []Container {
	var out []Container
	for _, id := range p.composeIDs(ctx, dir, true) {
		ci, ok := inv.byID[id]
		if !ok {
			continue
		}
		out = append(out, Container{
			Service:    ci.service,
			Name:       ci.name,
			State:      ci.state,
			Status:     ci.status,
			Image:      ci.image,
			StartedAt:  ci.startedAt,
			FinishedAt: ci.finishedAt,
			ExitCode:   ci.exitCode,
			Ports:      p.listeningPorts(ci.pid),
		})
	}
	return out
}

// proxy is the shared reverse proxy, or nil when there is none.
func (p *Probe) proxy(ctx context.Context, inv dockerInventory) *Proxy {
	if !dirExists(p.path(ProxyDir)) {
		return nil
	}
	pr := &Proxy{State: "stopped", Status: "not created"}
	pr.Network = firstIndented(p.path(filepath.Join(ProxyDir, "compose.yml")), "name:")
	pr.Image = firstIndented(p.path(filepath.Join(ProxyDir, "compose.yml")), "image:")
	if pr.Network == "" {
		pr.Network = "?"
	}
	if pr.Image == "" {
		pr.Image = "?"
	}
	for _, c := range inv.byID {
		if c.name != "komizo-proxy" {
			continue
		}
		pr.State = c.state
		pr.Status = c.status
		pr.StartedAt, pr.FinishedAt = c.startedAt, c.finishedAt
		break
	}
	// The on-demand TLS gate, if one is configured. A wildcard hostname needs
	// it, and its absence is the whole explanation for a wildcard deploy that
	// fails. The directive is the only line whose first field is "ask".
	for _, ln := range readLines(p.path(Caddyfile)) {
		f := strings.Fields(ln)
		if len(f) >= 2 && f[0] == "ask" {
			pr.TLSAsk = f[1]
			break
		}
	}
	return pr
}

// network is the shared network and who is attached under what alias.
func (p *Probe) network(ctx context.Context, pr *Proxy) *Network {
	name := "edge"
	if pr != nil && pr.Network != "" && pr.Network != "?" {
		name = pr.Network
	}
	out, err := p.docker(ctx, "network", "inspect", name, "--format",
		"{{.Driver}}"+dsep+"{{range .IPAM.Config}}{{.Subnet}}{{end}}")
	if err != nil {
		return nil
	}
	n := &Network{Name: name}
	f := strings.Split(strings.TrimSpace(out), dsep)
	if len(f) >= 1 {
		n.Driver = f[0]
	}
	if len(f) >= 2 {
		n.Subnet = f[1]
	}

	// Aliases are per-endpoint, so they come from the container rather than from
	// the network. Docker adds the short id as one; harmless, since it is unique
	// and cannot cause a false collision.
	members, err := p.docker(ctx, "network", "inspect", name, "--format",
		`{{range $k, $v := .Containers}}{{$v.Name}}`+dsep+`{{$k}}
{{end}}`)
	if err != nil {
		return n
	}
	for _, ln := range strings.Split(members, "\n") {
		f := strings.Split(strings.TrimSpace(ln), dsep)
		if len(f) < 2 || f[0] == "" {
			continue
		}
		m := NetworkMember{Container: f[0]}
		al, err := p.docker(ctx, "inspect", f[1], "--format",
			`{{range $n, $c := .NetworkSettings.Networks}}{{if eq $n "`+name+`"}}{{range $c.Aliases}}{{.}},{{end}}{{end}}{{end}}`)
		if err == nil {
			m.Aliases = splitList(strings.TrimSpace(al))
		}
		n.Members = append(n.Members, m)
	}
	return n
}

// firstIndented pulls the value off the first "  key: value" line in a compose
// file. Enough for the two fields the proxy's own compose is read for, and
// deliberately not a YAML parser: this reads a file komizo itself writes.
func firstIndented(path, key string) string {
	for _, ln := range readLines(path) {
		t := strings.TrimSpace(ln)
		if v, ok := strings.CutPrefix(t, key); ok && ln != t {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
