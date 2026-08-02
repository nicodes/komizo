package box

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Everything docker is asked, asked twice.
//
// TWO calls for the whole box, however many apps are on it: one `ps -a` and one
// `inspect` over every id it returned. Membership, aliases, mounts, timestamps
// and pids all come out of those, and nothing below this line talks to docker
// again.
//
// That is the property worth defending, because the cost is per CALL rather
// than per container. Asking per app instead -- a `compose ps` to find an app's
// containers, an `inspect` for each one's service and pid, another for its
// mounts -- put a six-app box at roughly eighty invocations per report, on a
// five-second poll. The shell this replaced was rewritten once for exactly this
// reason and said so in its own comments; it would have been a poor trade to
// port the probe and lose the lesson.
//
// Membership comes from the compose project's working directory, which compose
// records as a label. Matching on the project NAME would not do: compose
// derives that from the directory and normalises it, so an app under a custom
// --app-dir would not match its own containers.

// dockerInventory is every container on the box, indexed two ways.
type dockerInventory struct {
	byID map[string]*containerInfo
	// byDir is the containers of one app, keyed by the directory its compose
	// file lives in -- which is what an app's state file records as APP_DIR.
	byDir map[string][]*containerInfo
}

type containerInfo struct {
	id      string
	name    string
	state   string
	status  string
	service string
	image   string
	// workingDir is the compose project directory this container belongs to.
	// Empty for anything docker is running that compose did not create, which
	// is not komizo's business and is left out of every app.
	workingDir string

	startedAt  time.Time
	finishedAt time.Time
	exitCode   int
	pid        int

	// networks is alias list by network name, for the clash check. Per-endpoint,
	// so it comes from the container rather than from the network.
	networks map[string][]string
	// mounts is this container's named volumes and where they live on the host.
	mounts []mountInfo
}

type mountInfo struct{ name, source string }

// The separators between fields of one record.
//
// docker's --format writes whatever is asked for, and a container name or an
// image reference can hold almost anything -- but not a tab, and not a newline.
// The two inner ones only ever separate values docker itself generates: network
// names, aliases and volume names, all of which are restricted to
// [a-zA-Z0-9][a-zA-Z0-9_.-]*.
const (
	dsep    = "\t"
	dlist   = " "
	dassign = "="
)

func (p *Probe) dockerInventory(ctx context.Context) dockerInventory {
	inv := dockerInventory{byID: map[string]*containerInfo{}, byDir: map[string][]*containerInfo{}}

	// .State is the machine-readable word (running, exited); .Status is docker's
	// own prose (Up 3 hours), which is what a person actually wants to read.
	out, err := p.docker(ctx, "ps", "-a", "--no-trunc", "--format",
		strings.Join([]string{
			"{{.ID}}", "{{.Names}}", "{{.State}}", "{{.Status}}",
			`{{.Label "com.docker.compose.service"}}`, "{{.Image}}",
			`{{.Label "com.docker.compose.project.working_dir"}}`,
		}, dsep))
	if err != nil {
		return inv
	}
	var ids []string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), dsep)
		if len(f) < 7 || f[0] == "" {
			continue
		}
		c := &containerInfo{
			id: f[0], name: f[1], state: f[2], status: f[3],
			service: f[4], image: f[5], workingDir: f[6],
		}
		inv.byID[c.id] = c
		ids = append(ids, c.id)
		if c.workingDir != "" {
			d := filepath.Clean(c.workingDir)
			inv.byDir[d] = append(inv.byDir[d], c)
		}
	}
	if len(ids) == 0 {
		return inv
	}

	// Everything ps cannot say. Timestamps rather than prose, because ps offers
	// only .RunningFor (prose) and .CreatedAt (creation, which a restart does
	// not move); plus the pid the cgroup and namespace reads need, the aliases
	// the clash check needs, and the mounts the volume walk needs.
	args := append([]string{"inspect", "--format", strings.Join([]string{
		"{{.Id}}",
		"{{.State.StartedAt}}", "{{.State.FinishedAt}}", "{{.State.ExitCode}}", "{{.State.Pid}}",
		`{{range $n, $c := .NetworkSettings.Networks}}{{$n}}` + dassign +
			`{{range $c.Aliases}}{{.}},{{end}}` + dlist + `{{end}}`,
		`{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}` + dassign + `{{.Source}}` + dlist + `{{end}}{{end}}`,
	}, dsep)}, ids...)
	out, err = p.docker(ctx, args...)
	if err != nil {
		return inv
	}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), dsep)
		if len(f) < 7 {
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
		c.networks = parseNetworks(f[5])
		c.mounts = parseMounts(f[6])
	}
	return inv
}

// parseNetworks reads "netA=alias1,alias2, netB=alias3,".
//
// Docker adds the container's own short id as an alias. Harmless: it is unique,
// so it cannot cause a false clash.
func parseNetworks(s string) map[string][]string {
	out := map[string][]string{}
	for _, e := range strings.Split(s, dlist) {
		name, aliases, ok := strings.Cut(e, dassign)
		if !ok || name == "" {
			continue
		}
		out[name] = splitList(aliases)
	}
	return out
}

// parseMounts reads "vol1=/host/path vol2=/host/path".
func parseMounts(s string) []mountInfo {
	var out []mountInfo
	for _, e := range strings.Split(s, dlist) {
		name, src, ok := strings.Cut(e, dassign)
		if !ok || name == "" || src == "" {
			continue
		}
		out = append(out, mountInfo{name: name, source: src})
	}
	return out
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

// forDir is one app's containers.
//
// Asked with everything, so a container that exited is listed as exited instead
// of vanishing -- a stack that died is exactly what you are looking for here,
// and an absent row reads as "no such service".
func (inv dockerInventory) forDir(dir string) []*containerInfo {
	if dir == "" {
		return nil
	}
	return inv.byDir[filepath.Clean(dir)]
}

// containers is one app's containers, named individually rather than counted.
//
// A count says three are up; it cannot say WHICH of four is missing, and the
// missing one is the whole question when something 502s.
func (p *Probe) containers(dir string, inv dockerInventory) []Container {
	cs := inv.forDir(dir)
	out := make([]Container, 0, len(cs))
	for _, ci := range cs {
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
func (p *Probe) proxy(inv dockerInventory) *Proxy {
	if !dirExists(p.path(ProxyDir)) {
		return nil
	}
	compose := p.path(filepath.Join(ProxyDir, "compose.yml"))
	pr := &Proxy{
		State:   "stopped",
		Status:  "not created",
		Network: firstIndented(compose, "name:"),
		Image:   firstIndented(compose, "image:"),
	}
	if pr.Network == "" {
		pr.Network = "?"
	}
	if pr.Image == "" {
		pr.Image = "?"
	}
	for _, c := range inv.byID {
		if c.name != proxyContainer {
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

// proxyContainer is what the shared proxy is always called. Fixed by
// alpine-proxy.sh, which sets container_name.
const proxyContainer = "komizo-proxy"

// network is the shared network and who is attached under what alias.
//
// The members come from the containers already read, not from `network
// inspect`: that would name them but not their aliases, and the aliases are the
// entire point -- Caddy reaches an app by alias, so two containers claiming one
// name is the whole explanation for a 502 that nothing else on the box reveals.
func (p *Probe) network(ctx context.Context, pr *Proxy, inv dockerInventory) *Network {
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
	for _, c := range inv.sorted() {
		aliases, ok := c.networks[name]
		if !ok {
			continue
		}
		n.Members = append(n.Members, NetworkMember{Container: c.name, Aliases: aliases})
	}
	return n
}

// sorted is every container by name, so a report of the same box twice is the
// same document. Map order is not, and a report that reshuffles itself every
// minute is one nothing can usefully diff.
func (inv dockerInventory) sorted() []*containerInfo {
	out := make([]*containerInfo, 0, len(inv.byID))
	for _, c := range inv.byID {
		out = append(out, c)
	}
	sortBy(out, func(c *containerInfo) string { return c.name })
	return out
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
