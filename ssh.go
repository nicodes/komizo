package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
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

// knownHostsField is how a host appears in a known_hosts line: bare for port
// 22, bracketed otherwise.
func (t target) knownHostsField() string {
	if t.port == 22 {
		return t.host
	}
	return "[" + t.host + "]:" + strconv.Itoa(t.port)
}

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
func (t target) reachable() bool {
	_, err := t.quiet("true")
	return err == nil
}

// runScript pipes a script to the far end and runs it there, with its output
// streamed straight through so a long bootstrap shows progress as it happens.
// env is prepended as VAR='value' assignments; values must already be safe to
// single-quote, which every caller validates first.
func (t target) runScript(script string, env map[string]string) error {
	var b strings.Builder
	for _, k := range sortedKeys(env) {
		fmt.Fprintf(&b, "%s='%s' ", k, env[k])
	}
	b.WriteString("sh -s")

	c := exec.Command("ssh", t.sshArgs(b.String())...)
	c.Stdin = strings.NewReader(script)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	// stable order so the command line is reproducible between runs
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
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
