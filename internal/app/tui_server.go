package app

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/nicodes/komizo/scripts"
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
		// A log is the one thing on this screen an outsider can write into:
		// anything an app records about a request carries whatever was in that
		// request. Rendered raw, an escape sequence in it drives the terminal.
		return logsMsg{container: key, lines: scrub(out)}
	}
}

// containerLogCmd reads one container's log. The name came from the inventory,
// which read it out of docker, so it is docker's own string.
func containerLogCmd(name string) string {
	return "docker logs --tail 40 " + shQuote(name)
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

// stackCmd is one lifecycle verb against an app's whole compose project.
//
// Quoted by shQuote rather than by wrapping in quote characters and relying on
// the value not containing any. The directory does come from the box's own
// state file, which root wrote, and komizo constrains it before it ever gets
// there -- but that made the safety of this line a fact about two other files,
// and every value here arrives from the far end.
func stackCmd(a appRow, verb string) string {
	dir := shQuote(a.dir)
	return fmt.Sprintf("docker compose -f %s --project-directory %s %s",
		shQuote(a.dir+"/compose.yml"), dir, verb)
}

// containerCmd acts on one container by the name docker itself reported.
func containerCmd(name, verb string) string {
	return fmt.Sprintf("docker %s %s", verb, shQuote(name))
}

// startServerUpdate re-runs the Docker half only. Deliberately not the proxy,
// and deliberately not komizo's own scripts: bundling them would mean a routine
// Docker update installed a proxy on a box that chose not to have one, and
// rewrote scripts nobody asked it to touch.
func (m model) startServerUpdate() tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	net := m.net.name
	if net == "" {
		net = defaultNetwork
	}
	go func() {
		c := exec.Command("ssh", t.sshArgs(envPrefix(map[string]string{"SHARED_NETWORK": net})+"sh -s")...)
		if err := stream(ch, c, scripts.AlpineInitScript); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("server setup failed -- see the output above")}
			return
		}
		ch <- runDoneMsg{}
	}()
	return m.run.wait()
}

// proxyLine is the proxy's state and the network it fronts, one line: the two
// are read together -- "can anything reach the apps" -- and the network's only
// interesting state of its own is being missing.
func (m model) proxyLine() (string, string) {
	p := m.proxy
	if m.busy[proxyContainer] || m.settling[proxyContainer] {
		return spinner(m.spin), "working…"
	}
	var g, t string
	switch {
	case !p.installed:
		g, t = dot(""), "not installed — apps publish their own ports"
	// The word stays here, unlike on a container row. This row is LABELLED
	// "proxy", and a bare duration under that label answers a question nobody
	// asked -- five minutes of what? On a container the dot and the columns
	// around it already say, which is why the word is redundant there and not
	// here.
	case !p.running():
		g, t = dot("err"), "stopped  "+since(p.finishedAt)
	default:
		g, t = dot("ok"), "running  "+since(p.startedAt)
	}
	// The network, after whatever the proxy has to say. A missing one outranks
	// the proxy's own dot: a running proxy on a box whose apps cannot reach
	// each other is not a green row. The fix is re-running setup, which lives
	// on the docker row.
	if m.net.name == "" {
		// Short enough to survive a narrow terminal: the frame cuts rows, and
		// a hint that gets cut is no hint. The consequence -- apps cannot
		// reach each other -- is what the red dot is for.
		return dot("err"), t + "  ·  no shared network — re-run setup on the docker row"
	}
	net := m.net.name
	if m.net.driver != "" {
		net += ", " + m.net.driver
	}
	if m.net.subnet != "" {
		net += ", " + m.net.subnet
	}
	line := t + "  ·  " + net

	// The on-demand TLS gate. A wildcard hostname cannot get an ordinary
	// certificate, so it needs this -- and a wildcard app with no gate is a
	// deploy that fails with nothing else on this page saying why. Surface the
	// gate when set, and warn (outranking the proxy's own dot) when one is
	// needed and missing. Pressing t sets it.
	switch {
	case m.anyWildcard() && m.proxy.tlsAsk == "":
		return dot("warn"), line + "  ·  wildcard needs a TLS gate — press t"
	case m.proxy.tlsAsk != "":
		return g, line + "  ·  TLS gate on"
	}
	return g, line
}

// anyWildcard reports whether any app on the box declares a wildcard hostname,
// which is what makes the proxy's on-demand TLS gate load-bearing.
func (m model) anyWildcard() bool {
	for _, a := range m.apps {
		if a.hasWildcard() {
			return true
		}
	}
	return false
}

func orDash(s string) string {
	if s == "" {
		return dimStyle.Render("—")
	}
	return s
}

// startKomizoUpdate rewrites what komizo installs on the box: the sampler and
// its schedule.
//
// The only thing komizo owns here besides the proxy. Everything else it runs on
// a server -- the inventory, the request counts, the cgroup reads -- is piped
// over SSH on every poll and installed nowhere, so it updates the moment you run
// a newer komizo. This exists because a cron job cannot work that way.
func (m model) startKomizoUpdate() tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		if err := streamSampler(ch, t); err != nil {
			ch <- runDoneMsg{err: err}
			return
		}
		ch <- runDoneMsg{}
	}()
	return m.run.wait()
}
