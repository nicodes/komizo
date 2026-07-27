package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// The box itself: Docker, the shared network, the proxy, and what is wrong.
//
// These were once three screens, then one, and are now the block at the top of
// the app list. Each collapse was the same realisation: the answer to "is this
// server healthy and can it reach my apps" is spread across all of them, and
// anything you have to navigate to is something you find out late.

const proxyProject = "komizo-proxy"

// proxyCompose is the prefix for acting on the proxy stack. Pinned to the
// project name rather than the directory, because a compose project cannot be
// named after a directory beginning with an underscore.
func proxyCompose(verb string) string {
	return fmt.Sprintf("docker compose -f %s/compose.yml -p %s %s", proxyDir, proxyProject, verb)
}

type logsMsg struct {
	container string
	lines     string
	err       error
}

// fetchLogs pulls the tail of a log -- one container's, or a whole app's.
//
// Not just the proxy's: the proxy's is where Caddy records its certificate
// work, and an app's is where the app says why it will not start. Both are the
// answer to "it is running but not working", which is the failure this
// interface is least able to diagnose on its own.
//
// key identifies what is being shown, so the pane can be toggled shut by the
// same row that opened it and a slow fetch cannot overwrite a newer one.
func fetchLogs(t target, key, cmd string) tea.Cmd {
	return func() tea.Msg {
		out, err := t.quiet(cmd + " 2>&1")
		if err != nil && strings.TrimSpace(out) == "" {
			return logsMsg{container: key,
				err: fmt.Errorf("could not read that log -- is it created yet?")}
		}
		return logsMsg{container: key, lines: out}
	}
}

// containerLogCmd reads one container's log. The name came from the inventory,
// which read it out of docker, so it is docker's own string.
func containerLogCmd(name string) string {
	return "docker logs --tail 40 '" + name + "'"
}

// stackLogCmd reads every service in an app at once, interleaved.
func stackLogCmd(a appRow) string {
	return stackCmd(a, "logs --tail 40 --no-color")
}

// opDoneMsg is a lifecycle action finishing. key identifies the row that was
// busy, so the spinner stops on the right one.
type opDoneMsg struct {
	key string
	err error
}

// spinMsg drives the spinner. Only scheduled while something is in flight.
type spinMsg struct{}

func spinTick() tea.Cmd {
	return tea.Tick(110*time.Millisecond, func(time.Time) tea.Msg { return spinMsg{} })
}

// runOp performs one lifecycle command without taking over the screen.
//
// Start and stop are inline for a reason: they are quick, they are reversible
// by pressing the same key again, and routing them through a confirmation and a
// full-page output stream made "restart this thing" a four-keystroke errand.
// What replaced both is the spinner on the row itself -- the feedback is where
// you are already looking.
//
// The output is captured rather than streamed, and surfaced only if it fails.
// A successful `docker stop` has nothing to say that the refreshed list will
// not show better.
func runOp(t target, key, cmd string) tea.Cmd {
	return func() tea.Msg {
		c := exec.Command("ssh", t.sshArgs("sh -s")...)
		c.Stdin = strings.NewReader("set -e\n" + cmd + "\n")
		out, err := c.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if i := strings.LastIndex(msg, "\n"); i >= 0 {
				msg = msg[i+1:] // the last line is the one that says why
			}
			if msg == "" {
				msg = err.Error()
			}
			return opDoneMsg{key: key, err: fmt.Errorf("%s", msg)}
		}
		return opDoneMsg{key: key}
	}
}

// startShell runs one command on the box, streaming its output to the run pane.
// Kept for the long operations -- setup, install, removal -- where the output
// is the point and a spinner would hide it.
func (m model) startShell(cmd, title string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		c := exec.Command("ssh", t.sshArgs("sh -s")...)
		if err := stream(ch, c, "set -e\n"+cmd+"\n"); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("could not %s -- see the output above", title)}
			return
		}
		ch <- runDoneMsg{}
	}()
	return m.run.wait()
}

// startProxyAction runs one lifecycle command against the proxy stack.
//
// `up -d` rather than `start` for the start case: start fails on a container
// that was removed rather than stopped, and recreating it is what someone
// pressing "start" means either way.
func (m model) startProxyAction(verb, title string) tea.Cmd {
	return m.startShell("cd "+proxyDir+"\n"+proxyCompose(verb), title+" the proxy")
}

// stackCmd is one lifecycle verb against an app's whole compose project.
//
// Quoting is single-quote only, and that is sufficient here rather than lucky:
// the directory comes from the app's own deploy script, which root wrote, and
// the paths komizo generates are constrained to [A-Za-z0-9._/-] by validate.go
// before they ever reach the box.
func stackCmd(a appRow, verb string) string {
	return fmt.Sprintf("docker compose -f '%s/compose.yml' --project-directory '%s' %s",
		a.dir, a.dir, verb)
}

// containerCmd acts on one container by the name docker itself reported.
func containerCmd(name, verb string) string {
	return fmt.Sprintf("docker %s '%s'", verb, name)
}

// startServerUpdate re-runs the server half only. Deliberately not the proxy:
// bundling them would mean a routine Docker update could install a proxy on a
// box that chose not to have one.
func (m model) startServerUpdate() tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	net := m.net.name
	if net == "" {
		net = defaultNetwork
	}
	go func() {
		c := exec.Command("ssh", t.sshArgs(envPrefix(map[string]string{"SHARED_NETWORK": net})+"sh -s")...)
		if err := stream(ch, c, AlpineInitScript); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("server setup failed -- see the output above")}
			return
		}
		ch <- runDoneMsg{}
	}()
	return m.run.wait()
}

// knownHostsLine summarises the SSH_KNOWN_HOSTS value in one line.
//
// It belongs on the server rather than on an app: the keys are the BOX's, and
// every app pins the same ones. It used to appear only in the output of adding
// an app, which meant wanting it again meant re-running setup.
//
// Summarised rather than printed in full. It is one line per name per key --
// six for a box with two names -- and this now sits above the app list, which
// is the thing people actually came to look at. What you need at a glance is
// that it exists and which names it covers; the value itself is one keypress
// away and goes to the clipboard, which is where it was always headed.
func (m model) knownHostsLine() (string, string) {
	if len(m.srv.hostKeys) == 0 {
		return "", "—"
	}
	names := m.tgt.knownHostsNames()
	n := len(names) * len(m.srv.hostKeys)
	unit := "lines"
	if n == 1 {
		unit = "line"
	}
	// No status glyph, deliberately. Connecting by address once carried a
	// warning here, on the reasoning that CI probably dials a name that is not
	// in the value -- but that is a guess, not a fact, and the row already
	// lists exactly which names are covered for anyone who wants to check.
	//
	// The real signal is unambiguous and arrives where it matters: a deploy to
	// a name that is not pinned fails with "no entry for <name>". A coloured
	// dot that might mean that is worth less than the failure that says it.
	return "", fmt.Sprintf("%d %s for %s", n, unit, strings.Join(names, ", "))
}

func (m model) networkLine() (string, string) {
	n := m.net
	if n.name == "" {
		// The fix is re-running setup, which lives on the docker row -- named
		// here because "u" used to do it and no longer exists.
		return dot("err"), "none — apps cannot reach each other; re-run setup on the docker row"
	}
	meta := n.driver
	if n.subnet != "" {
		meta += ", " + n.subnet
	}
	return dot("ok"), n.name + "  " + meta
}

func (m model) proxyLine() (string, string) {
	p := m.proxy
	if m.busy[proxyContainer] || m.settling[proxyContainer] {
		return spinner(m.spin), "working…"
	}
	switch {
	case !p.installed:
		return dot(""), "not installed — apps publish their own ports"
	// The word stays here, unlike on a container row. This row is LABELLED
	// "status", and a bare duration under that label answers a question nobody
	// asked -- five minutes of what? On a container the dot and the columns
	// around it already say, which is why the word is redundant there and not
	// here.
	case !p.running():
		return dot("err"), "stopped  " + since(p.finishedAt)
	default:
		return dot("ok"), "running  " + since(p.startedAt)
	}
}

func orDash(s string) string {
	if s == "" {
		return dimStyle.Render("—")
	}
	return s
}
