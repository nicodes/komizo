package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
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
	t := target{user: "root", port: 22}
	if i := strings.Index(s, "@"); i >= 0 {
		t.user, s = s[:i], s[i+1:]
	}
	if s == "" {
		return t, fmt.Errorf("no hostname in %q", s)
	}
	t.host = s
	return t, nil
}

func (t target) addr() string { return t.user + "@" + t.host }

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
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	// Only force a port when the user asked for one. Passing -p unconditionally
	// would override a Port set in their ~/.ssh/config for this host, which is
	// the opposite of deferring to their existing setup.
	if t.portExplicit {
		args = append(args, "-p", strconv.Itoa(t.port))
	}
	args = append(args, t.addr())
	return append(args, extra...)
}

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
// remote command. Values must already be safe to single-quote, which every
// caller validates before connecting -- see validate.go.
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
		fmt.Fprintf(&b, "%s='%s' ", k, env[k])
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
