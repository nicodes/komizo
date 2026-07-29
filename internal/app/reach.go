package app

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Why a connection failed, and what to say about it.
//
// This used to be a bool, and every failure got the same message: "cannot SSH
// in as root without a password". On a freshly created server that is simply
// wrong -- the key is fine, the host is just one nobody has met before -- and it
// sent people off to run ssh-copy-id, which is not the fix and does not help.
// The four cases have four different remedies, so they get four messages.
type reachKind int

const (
	reachOK reachKind = iota
	reachUnknownHost
	reachChangedHost
	reachAuth
	reachNetwork
	reachOther
)

type reachResult struct {
	kind reachKind
	raw  string // ssh's own words, for the cases we cannot improve on
}

func (r reachResult) ok() bool { return r.kind == reachOK }

// probe opens a session and classifies the failure. Matched on ssh's stderr:
// its exit status is 255 for everything, so the text is the only signal.
func (t target) probe() reachResult {
	c := exec.Command("ssh", t.sshArgs("true")...)
	var errBuf strings.Builder
	c.Stderr = &errBuf
	if err := c.Run(); err == nil {
		return reachResult{kind: reachOK}
	}
	raw := strings.TrimSpace(errBuf.String())
	return reachResult{kind: classify(raw), raw: raw}
}

// classify maps ssh's stderr to a reason. Split out from probe so it can be
// tested against real captured output without needing a server: ssh exits 255
// for every one of these, so the text is the only thing distinguishing them.
func classify(raw string) reachKind {
	low := strings.ToLower(raw)
	switch {
	// Order matters: a changed key also prints "Host key verification failed",
	// and it is the one case that must never be mistaken for a first meeting.
	case strings.Contains(low, "remote host identification has changed"),
		strings.Contains(low, "host key for") && strings.Contains(low, "changed"):
		return reachChangedHost
	case strings.Contains(low, "host key verification failed"),
		strings.Contains(low, "no matching host key"),
		strings.Contains(low, "key is not known"):
		return reachUnknownHost
	case strings.Contains(low, "permission denied"),
		strings.Contains(low, "too many authentication failures"):
		return reachAuth
	case strings.Contains(low, "could not resolve"),
		strings.Contains(low, "connection refused"),
		strings.Contains(low, "connection timed out"),
		strings.Contains(low, "no route to host"),
		strings.Contains(low, "network is unreachable"),
		strings.Contains(low, "operation timed out"):
		return reachNetwork
	}
	return reachOther
}

// ensureReachable is the preflight every command runs: probe, optionally accept
// an unseen host key, and explain the failure if there still is one.
//
// Shared because the error text offers --accept-host-key, and a command that
// printed that advice without accepting the flag sent people to a dead end.
func ensureReachable(t target, acceptUnknown bool) error {
	r := t.probe()
	if !r.ok() && r.kind == reachUnknownHost && acceptUnknown {
		if err := acceptHostKey(t, true); err != nil {
			return err
		}
		r = t.probe()
	}
	if !r.ok() {
		return r.explain(t)
	}
	return nil
}

// summary is the same diagnosis as explain, in one line, for the footer.
//
// explain is several paragraphs with a command to run in the middle of it --
// right for a shell, wrong for a status line under an input field, where the
// next step is always "type a different address" or "fix it and press enter".
func (r reachResult) summary(t target) string {
	switch r.kind {
	case reachUnknownHost:
		return t.host + " has not been seen before"
	case reachChangedHost:
		return t.host + " is presenting a different host key than last time"
	case reachAuth:
		return "no key on this machine is accepted by " + t.addr()
	case reachNetwork:
		return "could not reach " + t.host
	}
	if r.raw != "" {
		// ssh's first line: what follows is usually a debug trail.
		return strings.SplitN(r.raw, "\n", 2)[0]
	}
	return "could not connect to " + t.addr()
}

// explain turns a failure into something with a next step in it.
func (r reachResult) explain(t target) error {
	switch r.kind {
	case reachUnknownHost:
		return fmt.Errorf("%s is a host this machine has never connected to.\n\n"+
			"    Its key is not in ~/.ssh/known_hosts, so ssh refuses to continue --\n"+
			"    nothing is wrong with your key or the server. Meet it once:\n\n"+
			"        ssh %s\n\n"+
			"    Check the fingerprint it shows against your provider's console, accept,\n"+
			"    then run this again. Or let komizo do it: --accept-host-key",
			t.host, t.addr())

	case reachChangedHost:
		return fmt.Errorf("the host key for %s has CHANGED since you last connected.\n\n"+
			"    Either the server was rebuilt, or something is impersonating it.\n"+
			"    komizo will not connect either way. If you rebuilt it deliberately:\n\n"+
			"        ssh-keygen -R %s\n\n"+
			"    If you did not, stop and find out why before going further.\n\n%s",
			t.host, t.host, indent(r.raw))

	case reachAuth:
		return fmt.Errorf("%s refused the key.\n\n"+
			"    komizo needs an existing password-less login to work from; it does not\n"+
			"    create your access, only the deploy account's. If you normally type a\n"+
			"    password:\n\n        ssh-copy-id %s\n\n%s",
			t.addr(), t.addr(), indent(r.raw))

	case reachNetwork:
		return fmt.Errorf("cannot reach %s.\n\n%s", t.host, indent(r.raw))

	case reachOther:
		return fmt.Errorf("could not connect to %s.\n\n%s", t.addr(), indent(r.raw))
	}
	return nil
}

func indent(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, ln := range strings.Split(s, "\n") {
		b.WriteString("    " + ln + "\n")
	}
	return b.String()
}

// acceptHostKey records the server's key in known_hosts after showing its
// fingerprint.
//
// This is trust-on-first-use and is labelled as such: the key comes from
// whatever answers on the port, so it is exactly as trustworthy as the network
// between here and there. It is the same trust `ssh` asks you to extend on a
// first connection -- komizo only puts the fingerprint next to the question
// instead of making you run a second command to see it.
//
// Deliberately separate from how CI's known_hosts is produced: that is read out
// of /etc/ssh on the server over an already-authenticated session, and never
// scanned.
func acceptHostKey(t target, assumeYes bool) error {
	scan, err := scanHostKeys(t)
	if err != nil {
		return err
	}

	if !assumeYes {
		fmt.Printf("\n  %s has not been seen before. Its fingerprints are:\n\n", t.host)
		for _, ln := range fingerprints(scan) {
			fmt.Printf("      %s\n", ln)
		}
		fmt.Printf("\n  These came from the network, not from the server's own /etc/ssh --\n" +
			"  nothing here has verified them. Compare against your provider's\n" +
			"  console before accepting.\n\n  Add to known_hosts? [y/N] ")
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			return fmt.Errorf("not accepted")
		}
	}

	kh, err := writeKnownHosts(scan)
	if err != nil {
		return err
	}
	note("added %s to %s", t.host, kh)
	if assumeYes {
		// --accept-host-key (or the scripted path) took the key without a person
		// comparing the fingerprint. Say so plainly: it is only as trustworthy as
		// the network between here and the box at this moment.
		warn("accepted %s's host key without verification (--accept-host-key);\n"+
			"    it came from the network, not the server's console -- trust the network accordingly", t.host)
	}
	return nil
}

// scanHostKeys asks the network what keys the host presents. Nothing here has
// verified them -- that is the whole point of showing the fingerprints before
// anyone accepts them.
func scanHostKeys(t target) ([]byte, error) {
	args := []string{"-T", "5"}
	if t.port != 22 {
		args = append(args, "-p", fmt.Sprint(t.port))
	}
	args = append(args, t.host)
	scan, err := exec.Command("ssh-keyscan", args...).Output()
	if err != nil || len(strings.TrimSpace(string(scan))) == 0 {
		return nil, fmt.Errorf("could not reach %s to read its host key", t.host)
	}
	return scan, nil
}

// fingerprints is the scanned keys in the form a person can compare against a
// provider's console.
func fingerprints(scan []byte) []string {
	fp := exec.Command("ssh-keygen", "-l", "-f", "-")
	fp.Stdin = strings.NewReader(string(scan))
	out, _ := fp.Output()
	var lines []string
	for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if ln != "" {
			lines = append(lines, ln)
		}
	}
	return lines
}

// writeKnownHosts appends the scanned keys and returns the file it wrote to.
//
// Split out from acceptHostKey so the interface can use it: that function
// prints to stdout, which inside a full-screen program paints over the page.
//
// Lines already in the file are skipped. Accepting the same host twice -- which
// happens whenever a first connection is retried -- used to append the whole
// scan again, so a file anybody might have to read by hand grew a duplicate
// block per attempt.
func writeKnownHosts(scan []byte) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	kh := filepath.Join(home, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(kh), 0o700); err != nil {
		return "", err
	}

	have := map[string]bool{}
	if b, err := os.ReadFile(kh); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if ln = strings.TrimSpace(ln); ln != "" {
				have[ln] = true
			}
		}
	}
	var add strings.Builder
	for _, ln := range strings.Split(string(scan), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") || have[t] {
			continue
		}
		have[t] = true
		add.WriteString(t)
		add.WriteString("\n")
	}
	if add.Len() == 0 {
		return kh, nil
	}

	f, err := os.OpenFile(kh, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(add.String()); err != nil {
		return "", err
	}
	return kh, nil
}
