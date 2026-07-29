package app

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// target is a server we can reach over SSH.
//
// Commands shell out to the system ssh rather than using a Go SSH library. That
// keeps ~/.ssh/config, agent forwarding, jump hosts and any other local setup
// working exactly as they do when you ssh in by hand -- reimplementing that
// surface would be a lot of code and a lot of ways to behave differently from
// the user's expectations.
type target struct {
	user string // login user on the far end, usually root
	host string
	port int
	// portExplicit records whether the user passed --port. When they did not,
	// we defer to their ssh config rather than forcing a value.
	portExplicit bool

	// aliases are additional names this same server answers to. known_hosts is
	// matched on the exact name the client dialled, so a box set up by IP and
	// deployed to by hostname matches nothing -- CI stops with "no entry for
	// <name>" even though the keys are right there.
	aliases []string
}

func parseTarget(s string) (target, error) {
	orig := s
	t := target{user: "root", port: 22}
	if i := strings.Index(s, "@"); i >= 0 {
		t.user, s = s[:i], s[i+1:]
	}
	if s == "" {
		// The ORIGINAL, not what is left of it: reporting the remainder means
		// "root@" is rejected with `no hostname in ""`, which names nothing the
		// user typed.
		return t, fmt.Errorf("no hostname in %q", orig)
	}
	// The login user is validated here, at the one place every caller parses a
	// target, because addr() hands `user@host` to ssh as a single argv element:
	// an unchecked user beginning with '-' becomes an ssh option (ProxyCommand),
	// i.e. local command execution. The host is validated by callers after the
	// port is resolved.
	if err := validateLoginUser(t.user); err != nil {
		return t, err
	}
	t.host = s
	return t, nil
}

// resolveTarget turns a --host flag into a target with its port settled and its
// hostname checked.
//
// Every command did these six steps in the same order, and a command that got
// one wrong -- forgetting resolvePort, most likely -- would work perfectly
// against a box on port 22 and write known_hosts entries that match nothing
// against any other.
func resolveTarget(fs *flag.FlagSet, host string, port int) (target, error) {
	if host == "" {
		return target{}, fmt.Errorf("--host is required, e.g. --host root@myapp.example.com")
	}
	t, err := parseTarget(host)
	if err != nil {
		return target{}, err
	}
	if port < 1 || port > 65535 {
		return target{}, fmt.Errorf("--port must be 1-65535, got %d", port)
	}
	t.port = port
	t.portExplicit = portWasSet(fs)
	t.resolvePort()
	if err := validateHost(t.host); err != nil {
		return target{}, err
	}
	return t, nil
}

func (t target) addr() string { return t.user + "@" + t.host }

// hostDisplay is which BOX, without which login. The header wants this one: the
// account is always the same across a session and is not what distinguishes one
// terminal from another, so carrying it in a breadcrumb spends width on a
// constant. display() keeps the user, for the places that are about connecting.
func (t target) hostDisplay() string {
	if t.port == 22 {
		return t.host
	}
	return fmt.Sprintf("%s:%d", t.host, t.port)
}

// display is the address as a person should read it: the port only when it is
// not the one everybody assumes.
func (t target) display() string {
	if t.port == 22 {
		return t.addr()
	}
	return fmt.Sprintf("%s:%d", t.addr(), t.port)
}

// knownHostsField is how a host appears in a known_hosts line: bare for port
// 22, bracketed otherwise.
func (t target) knownHostsField() string { return t.knownHostsName(t.host) }

func (t target) knownHostsName(host string) string {
	if t.port == 22 {
		return host
	}
	return "[" + host + "]:" + strconv.Itoa(t.port)
}

// namedFor is this target with one app's extra names on it, for building that
// app's known_hosts value.
//
// A copy rather than a mutation: the names belong to the app, not to the
// connection, and the interface holds one target across every app on the box.
// They used to be merged onto it as apps were added, which meant an app's value
// carried the names of whatever else had been set up in the same session -- and
// lost them entirely on the next run, since nothing wrote them down.
func (t target) namedFor(names []string) target {
	t.aliases = names
	return t
}

// knownHostsNames is every name to write an entry for: the one we connected by,
// plus any aliases, de-duplicated and in a stable order.
func (t target) knownHostsNames() []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range append([]string{t.host}, t.aliases...) {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, t.knownHostsName(h))
	}
	return out
}

// isIP reports whether we connected to a literal address rather than a name.
// Worth knowing because CI almost always connects by name, so this is exactly
// when the entries we are about to write will not match.
func (t target) isIP() bool { return net.ParseIP(t.host) != nil }

func (t target) sshArgs(extra ...string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",

		// Never inherit a looser policy from the user's ssh config. With
		// StrictHostKeyChecking left at the default, an operator who set
		// `accept-new` (or `no`) would have komizo silently trust an unseen -- or
		// even a CHANGED -- host key, and then read that key back over the
		// connection as the value CI pins forever (hostkeys.go). The deliberate
		// trust-on-first-use path (reach.go) writes known_hosts before it
		// reconnects, so it still works with this set; nothing else should.
		"-o", "StrictHostKeyChecking=yes",

		// One connection, reused by everything that follows.
		//
		// The interface polls the box every five seconds and every operation
		// opens its own session, so without this each one paid a full TCP
		// handshake, key exchange and authentication -- and wrote a line into
		// the server's auth log for the privilege. The master persists briefly
		// after the last session so a poll, a log fetch and an operation in
		// quick succession share it, and a session that outlives the master is
		// simply a new connection rather than an error.
		//
		// %C hashes the whole destination (host, port, user, proxy), so two
		// targets cannot share a socket and the path stays short enough for the
		// unix socket limit that %h would blow past on a long hostname.
		//
		// A connection that stalls mid-stream is not covered by ConnectTimeout,
		// which only bounds the dial. Without these a poll against a box that
		// dropped off the network hangs forever, and the interface stops
		// refreshing with nothing on screen saying why.
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=3",
	}
	if p := controlPath(); p != "" {
		args = append(args,
			"-o", "ControlMaster=auto",
			"-o", "ControlPath="+p,
			"-o", "ControlPersist=60s",
		)
	}
	// Only force a port when the user asked for one. Passing -p unconditionally
	// would override a Port set in their ~/.ssh/config for this host, which is
	// the opposite of deferring to their existing setup.
	if t.portExplicit {
		args = append(args, "-p", strconv.Itoa(t.port))
	}
	args = append(args, t.addr())
	return append(args, extra...)
}

// controlPath is where the shared connection's socket lives, or "" when there
// is nowhere to put one.
//
// Under the user's own directory rather than /tmp: whoever can open that socket
// gets the authenticated session behind it, and ~/.ssh is already the directory
// whose permissions the user maintains for exactly that reason.
//
// Resolved once, and the directory created, because ssh does not fall back
// quietly -- given a path it cannot bind, it complains on stderr for every
// connection, which on a five-second poll is a permanent error message about
// something that is not the user's problem. No directory, no multiplexing.
var controlPath = sync.OnceValue(func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	// MkdirAll leaves an existing directory's mode alone, so tighten it: whoever
	// can open the control socket rides the authenticated session behind it.
	// ssh binds the socket itself at 0600, so this is depth -- but 0700 is the
	// mode ~/.ssh is meant to have anyway, and ssh refuses a looser one.
	_ = os.Chmod(dir, 0o700)
	return filepath.Join(dir, "komizo-%C")
})

// resolvePort asks ssh what port it will actually use for this host, so the
// known_hosts lines we build match. `ssh -G` prints the fully resolved
// configuration without connecting, taking ~/.ssh/config and defaults into
// account.
func (t *target) resolvePort() {
	if t.portExplicit {
		return
	}
	out, err := exec.Command("ssh", "-G", t.addr()).Output()
	if err != nil {
		return // fall back to the default already set
	}
	for _, ln := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(ln, "port "); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil && n > 0 {
				t.port = n
			}
			return
		}
	}
}

// run executes a command on the far end and returns its stdout, trimmed.
// Stderr is passed through so ssh's own diagnostics reach the user.
func (t target) run(cmd string) (string, error) {
	c := exec.Command("ssh", t.sshArgs(cmd)...)
	c.Stderr = os.Stderr
	out, err := c.Output()
	return strings.TrimRight(string(out), "\n"), err
}

// quiet is run with stderr suppressed, for probes where a failure is an
// expected answer rather than something to report.
func (t target) quiet(cmd string) (string, error) {
	c := exec.Command("ssh", t.sshArgs(cmd)...)
	out, err := c.Output()
	return strings.TrimRight(string(out), "\n"), err
}

// reachable reports whether we can open a session without a password.
//
// Kept only for callers that genuinely need a yes/no. Anything that reports a
// failure to a person should use probe() and explain(): the reason matters, and
// "cannot log in" is the wrong answer for three of the four ways this fails.
func (t target) reachable() bool { return t.probe().ok() }

// runScript pipes a script to the far end and runs it there, with its output
// streamed straight through so a long bootstrap shows progress as it happens.
func (t target) runScript(script string, env map[string]string) error {
	c := exec.Command("ssh", t.sshArgs(envPrefix(env)+"sh -s")...)
	c.Stdin = strings.NewReader(script)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

// envPrefix renders the environment as VAR='value' assignments in front of the
// remote command.
//
// Quoted by shQuote rather than by wrapping the value in quote characters and
// trusting it not to contain any. Callers do validate -- see validate.go -- but
// that made the safety of this line depend on a rule enforced three files away,
// and a caller who forgot it got a shell injection rather than a bad error
// message.
//
// Sorted so the command line is reproducible between runs, which matters when
// the thing you are comparing is two transcripts of the same operation.
func envPrefix(env map[string]string) string {
	ks := make([]string, 0, len(env))
	for k := range env {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		fmt.Fprintf(&b, "%s=%s ", k, shQuote(env[k]))
	}
	return b.String()
}

// runCapture pipes a script to the far end, runs it there, and returns its
// stdout. Used for read-only inventory where we want to parse the result
// rather than stream it.
func (t target) runCapture(script string) (string, error) {
	c := exec.Command("ssh", t.sshArgs("sh -s")...)
	c.Stdin = strings.NewReader(script)
	c.Stderr = os.Stderr
	out, err := c.Output()
	return strings.TrimRight(string(out), "\n"), err
}

// portWasSet reports whether --port appeared on the command line, as opposed to
// sitting at its default.
func portWasSet(fs *flag.FlagSet) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			set = true
		}
	})
	return set
}
