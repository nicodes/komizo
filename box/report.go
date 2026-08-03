// Package box is what runs ON a server: the probes that describe a machine, and
// the report they produce.
//
// It is imported by three programs that are not the same program and are not
// upgraded together. komizo-box runs on a server as root and WRITES a report.
// The komizo CLI runs on a laptop and READS one. The komizo service receives
// them from every box it knows about, each running whatever version it was last
// given. They share this package so the schema is a Go type checked by the
// compiler rather than a protocol three codebases agree about in prose.
//
// PUBLIC, not internal/, for that third reader: the service is a different
// module. A schema that only one module can express is a schema the other two
// have to restate, and a restated wire format is two definitions waiting to
// disagree. See Version for what that costs and what the rule is.
//
// Nothing in here may import internal/app. The CLI is allowed to know about the
// box; the box is not allowed to know about the interface.
package box

import "time"

// Version is the report schema, and the rule for changing it.
//
// ADD fields. Never rename one, never repurpose one, never change what a unit
// means. An old CLI reading a new report ignores what it does not know, and a
// new CLI reading an old report sees a zero -- both of which are survivable.
// A field that changed MEANING is not: it decodes perfectly and is wrong, on a
// screen somebody is using to decide whether their server is healthy.
//
// This is the cost of moving the probe from shell to a binary. The shell was
// shipped fresh from the laptop on every poll, so producer and consumer were
// always the same release and the wire format could change freely. It cannot
// now.
//
// Bumped only when a reader must refuse the whole document, which no addition
// warrants. Nothing does yet.
const Version = 1

// Report is one complete reading of a server.
//
// Everything here is derivable from the box by root. None of it is new data --
// it is what `komizo list` and the monitor already show, produced once by the
// machine that knows it rather than assembled from a dozen shell records.
//
// NEVER in this document: secret values, the contents of .env or secrets.env,
// registry tokens, private keys, or raw access-log lines. The first four are
// 600 root and this must not be the thing that copies them out; the last is the
// standing promise that request paths and client IPs stay on the box. See
// Metrics.
type Report struct {
	// V is the schema Version of the producer. Present so a reader can say
	// "this box speaks a report I do not understand" rather than silently
	// showing a screen of zeroes.
	V int `json:"v"`
	// At is when the probe ran, from the box's own clock.
	//
	// The box's, not the reader's. A report is written on a timer and read some
	// time later, and every duration on screen is measured from this. Using the
	// reader's clock would fold the staleness of the file into the age of every
	// container on it.
	At time.Time `json:"at"`

	Server Server `json:"server"`
	// Proxy and Network are absent, not empty, when there is none. A box with no
	// shared proxy is a state komizo offers to fix; a proxy record full of zeroes
	// reads as one that is installed and broken.
	Proxy   *Proxy   `json:"proxy,omitempty"`
	Network *Network `json:"network,omitempty"`

	Apps []App `json:"apps"`
	// Orphans are directories under /srv with no state file behind them --
	// usually a removal that did not finish.
	Orphans []string `json:"orphans,omitempty"`

	// System is what the box is spending right now: cumulative counters, not
	// rates. Two readings make a rate, and the reader owns the subtraction --
	// which also makes the interval explicit rather than assumed, so a poll that
	// arrived late measures the longer gap it actually covered.
	System System `json:"system"`

	// Problems is the diagnosis, computed here.
	//
	// This is most of the product and the reason the report is not just facts.
	// An alias clash, an app publishing routes while detached from the network,
	// a stopped proxy -- these are the failures that are invisible from outside,
	// where the box looks healthy and one hostname 502s.
	//
	// Computed on the box rather than by each reader because there are now
	// several readers -- the CLI, the TUI, and later a service and a phone --
	// and a diagnosis reimplemented four times is four chances to disagree about
	// whether a server is broken.
	Problems []Problem `json:"problems"`
}

// Schema is the version this document was written against. See Decode.
func (r Report) Schema() int { return r.V }

// Stale reports whether this reading is older than d.
//
// The check belongs here rather than in each reader: "how old is too old" is a
// property of how often the box writes, which is a fact this package owns.
func (r Report) Stale(now time.Time, d time.Duration) bool {
	return r.At.IsZero() || now.Sub(r.At) > d
}

// Server is the box itself, before any app is considered.
type Server struct {
	// State is ready | docker-stopped | bare. Checked before anything else here
	// is read: an uninitialised box is a state to show, not an error.
	State  string `json:"state"`
	Docker string `json:"docker,omitempty"`
	// OS is the distribution as it names itself -- PRETTY_NAME from
	// /etc/os-release. Read rather than assumed: komizo installs Alpine but is
	// pointed at existing servers too, and a row that says "alpine" about a
	// Debian box is wrong in the one place whose job is to state facts.
	OS      string `json:"os,omitempty"`
	UptimeS int64  `json:"uptime_s,omitempty"`

	// Komizo is what komizo last installed here, read back rather than assumed.
	// The alternative is for the interface to print what it WOULD install, which
	// is a fact about the laptop.
	Komizo KomizoInstall `json:"komizo"`

	// HostKeys are the box's own public keys, for the known_hosts value CI pins.
	// Public by definition -- what they need is integrity, not secrecy.
	HostKeys []HostKey `json:"host_keys,omitempty"`
}

func (s Server) Ready() bool { return s.State == "ready" }

// OSName is what the box runs, or what komizo installs when nothing has said
// otherwise -- a box whose probe never got as far as /etc/os-release.
func (s Server) OSName() string {
	if s.OS == "" {
		return "alpine"
	}
	return s.OS
}

// KomizoInstall is the stamp komizo wrote when it last set this box up.
type KomizoInstall struct {
	Installed bool `json:"installed"`
	// Version is the komizo release that provisioned the box; Stamp is the
	// content hash of what it wrote. Two different questions: which komizo set
	// this up, and would running the update change anything.
	Version string `json:"version,omitempty"`
	Stamp   string `json:"stamp,omitempty"`
	// Agent is the version of the binary that produced this report, which is not
	// necessarily the one that provisioned the box -- that is the whole point of
	// reporting it.
	Agent string `json:"agent,omitempty"`
}

type HostKey struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

// App is one deployed application.
type App struct {
	Name string `json:"name"`
	// User is the account CI deploys as -- komizo-<name>.
	User string `json:"user,omitempty"`
	Dir  string `json:"dir,omitempty"`
	// Version is what is deployed, from APP_VERSION in the app's .env. "none"
	// when nothing has been deployed yet.
	Version     string `json:"version,omitempty"`
	ConfigImage string `json:"config_image,omitempty"`
	// KnownAs are the names CI dials this app by, recorded when it was added.
	// The keys belong to the machine; these names belong to the repo.
	KnownAs []string `json:"known_as,omitempty"`

	// Stopped is a deliberate stop, held on the box.
	//
	// On the box, and never read from a service, because the deploy path must
	// not consult komizo -- see design/appify.md §2. It is also what keeps a
	// stopped app from paging anyone: down is an incident, stopped is a
	// decision, and nothing outside the box can tell them apart.
	Stopped   bool      `json:"stopped,omitempty"`
	StoppedBy string    `json:"stopped_by,omitempty"`
	StoppedAt time.Time `json:"stopped_at,omitzero"`

	Containers []Container `json:"containers,omitempty"`
	// Hosts is every name this app answers on, with the container the app said
	// serves it. The service is empty when the app did not say -- which is the
	// honest default, since nothing else on this machine could work it out.
	Hosts []Host `json:"hosts,omitempty"`
}

// Running is how many of the app's containers are up.
func (a App) Running() int {
	n := 0
	for _, c := range a.Containers {
		if c.State == "running" {
			n++
		}
	}
	return n
}

// Routes is every hostname the app publishes, in the order it declared them.
func (a App) Routes() []string {
	out := make([]string, 0, len(a.Hosts))
	seen := map[string]bool{}
	for _, h := range a.Hosts {
		if h.Name != "" && !seen[h.Name] {
			seen[h.Name] = true
			out = append(out, h.Name)
		}
	}
	return out
}

// Container is one container belonging to an app.
//
// Service is the name in compose.yml and is the one to lead with: it is what
// you wrote, what the shared proxy is pointed at, and what stays stable across
// restarts. Name is docker's, derived from it.
type Container struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	// State is docker's machine-readable word (running, exited, created);
	// Status is docker's own prose ("Up 3 hours"), which is what a person
	// actually wants to read.
	State  string `json:"state"`
	Status string `json:"status,omitempty"`
	Image  string `json:"image,omitempty"`

	// Timestamps rather than prose. "Up 3 hours" and "Exited (1) 2 minutes ago"
	// cannot be compared, added up, or rendered in one format, and every row on
	// the page shows a duration.
	StartedAt  time.Time `json:"started_at,omitzero"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	ExitCode   int       `json:"exit_code,omitempty"`

	// Ports is what this container is LISTENING on, read from its network
	// namespace rather than declared anywhere. Empty for a stopped container,
	// which has no namespace to read.
	//
	// Observed, not declared: EXPOSE is inherited from base images, so a Caddy
	// gate "exposes" 443 and 2019 it never binds.
	Ports []int `json:"ports,omitempty"`
}

// Host is one name an app answers on.
type Host struct {
	Name string `json:"name"`
	// Service is what the app said serves this name, from the arrow in its
	// hostnames file. It is the only thing on the machine that knows which
	// container a hostname reaches; without it every name lands on the gate,
	// which is true of the first hop and useless as an answer.
	Service string `json:"service,omitempty"`
}

// Proxy is the shared reverse proxy. Not an app: no deploy account, no config
// image, nothing from CI ever touches it.
type Proxy struct {
	State   string `json:"state"` // running | stopped
	Network string `json:"network,omitempty"`
	Image   string `json:"image,omitempty"`
	Status  string `json:"status,omitempty"`
	// TLSAsk is the on-demand TLS ask endpoint. A wildcard hostname needs one,
	// and its absence is the whole explanation for a wildcard deploy that fails.
	TLSAsk     string    `json:"tls_ask,omitempty"`
	StartedAt  time.Time `json:"started_at,omitzero"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
}

func (p Proxy) Running() bool { return p.State == "running" }

// Network is the shared docker network and -- the point of reporting it at all
// -- who is attached and under what alias. Caddy reaches an app by alias, so a
// container missing here, or one sharing an alias with another app, is the
// whole explanation for a 502 that nothing else on the box reveals.
type Network struct {
	Name    string          `json:"name"`
	Driver  string          `json:"driver,omitempty"`
	Subnet  string          `json:"subnet,omitempty"`
	Members []NetworkMember `json:"members,omitempty"`
}

type NetworkMember struct {
	Container string   `json:"container"`
	Aliases   []string `json:"aliases,omitempty"`
}

// Problem is one thing wrong with the box, named and explained.
//
// Kind is stable and machine-readable -- an alert rule matches on it. Detail is
// prose for a person and may be reworded freely; nothing should ever parse it.
type Problem struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	// App is which app it concerns, empty when it is the box's own.
	App string `json:"app,omitempty"`
}

// The problem kinds. Named constants because an alert rule matches on these,
// and a typo in a string literal produces a rule that silently never fires.
const (
	ProblemAliasClash   = "alias_clash"
	ProblemProxyStopped = "proxy_stopped"
	ProblemDetached     = "detached"
	ProblemOrphanDir    = "orphan_dir"
	ProblemNoTLSGate    = "no_tls_gate"
	ProblemAppDown      = "app_down"
)
