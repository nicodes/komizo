package app

import (
	"errors"
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
		// The words stay here, because the dot does not carry them: "not
		// installed" is a neutral dot, and a neutral dot names nothing on its own.
		g, t = dot(""), "not installed — apps publish their own ports"
	case !p.running():
		// No "stopped": the red dot says that. What the colour cannot say is how
		// long, so the duration is all that is left.
		g, t = dot("err"), since(p.finishedAt)
	default:
		// No "running" either: the green dot says it, and the value is the uptime.
		g, t = dot("ok"), since(p.startedAt)
	}
	// The network, after whatever the proxy has to say. A missing one outranks
	// the proxy's own dot: a running proxy on a box whose apps cannot reach
	// each other is not a green row. The fix is re-running setup, which lives
	// on the komizo server row.
	if m.net.name == "" {
		// Short enough to survive a narrow terminal: the frame cuts rows, and
		// a hint that gets cut is no hint. The consequence -- apps cannot
		// reach each other -- is what the red dot is for.
		return dot("err"), t + "  ·  no shared network — re-run setup on the komizo server row"
	}
	net := m.net.name
	if m.net.driver != "" {
		net += ", " + m.net.driver
	}
	if m.net.subnet != "" {
		net += ", " + m.net.subnet
	}
	return g, t + "  ·  " + net
}

// gateLine is the proxy's on-demand TLS gate, on its own row: the endpoint Caddy
// asks before issuing a certificate for a wildcard hostname. Its own row so the
// on/off state is a glance rather than a flag you have to remember -- forgetting
// it on a fresh box otherwise surfaces only as a failed wildcard deploy.
func (m model) gateLine() (string, string) {
	if m.busy[proxyContainer] || m.settling[proxyContainer] {
		return spinner(m.spin), "working…"
	}
	if m.proxy.tlsAsk != "" {
		// No "on": the green dot says it, and the value is the endpoint itself.
		return dot("ok"), m.proxy.tlsAsk
	}
	// Off. An amber dot only when something actually needs it -- a box with no
	// wildcard app is entitled to have no gate, and nagging it would train the
	// dot to be ignored. No "off" in the text: the dot's colour is the state, and
	// what is worth saying is why it matters or does not.
	if names := m.wildcardApps(); len(names) > 0 {
		return dot("warn"), strings.Join(names, ", ") + " need it; enter to set"
	}
	return dot(""), "only a wildcard hostname needs one"
}

// wildcardApps is the apps that declare a wildcard hostname, which are the ones
// the on-demand TLS gate is load-bearing for.
func (m model) wildcardApps() []string {
	var out []string
	for _, a := range m.apps {
		if a.hasWildcard() {
			out = append(out, a.name)
		}
	}
	return out
}

// anyWildcard reports whether any app on the box declares a wildcard hostname.
func (m model) anyWildcard() bool { return len(m.wildcardApps()) > 0 }

// startKomizoUpdate re-provisions the box: the same sequence as a fresh `komizo
// init`, run over a server that is already live.
//
// A fresh install rather than an agent reinstall, because "update" has one job --
// leave the box at the version of komizo in your hand -- and only re-running
// everything komizo installs can promise that. So: Docker and the network, then
// the agent (which stamps this version), then every app's own scripts, then the
// proxy.
//
// The per-app step is the one that was missing, and its absence is what made
// the sentence above false: an app's deploy-<app> is generated shell komizo
// writes and versions with everything else, and until komizo#58 nothing but
// `komizo add` ever rewrote it. See refresh.go.
//
// The proxy step is conditional. A box that was set up without one, or chose to
// stop it, should not have one reinstalled by a routine update -- so it runs
// only where a proxy already exists, and re-runs it with the network, image and
// TLS-gate the box already has, which is exactly what `p` on the proxy row does.
func (m model) startKomizoUpdate() tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	net := m.net.name
	if net == "" {
		net = defaultNetwork
	}
	proxyInstalled := m.proxy.installed
	img := m.proxy.image
	if img == "" {
		img = defaultProxy
	}
	tlsAsk := m.proxy.tlsAsk
	go func() {
		c := exec.Command("ssh", t.sshArgs(envPrefix(map[string]string{"SHARED_NETWORK": net})+"sh -s")...)
		if err := stream(ch, c, scripts.AlpineInitScript); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("server setup failed -- see the output above")}
			return
		}
		if err := streamAgent(ch, t); err != nil {
			ch <- runDoneMsg{err: err}
			return
		}

		// Carried to the end rather than returned here, for the reason
		// RunUpdate carries it: a broken record for one app is not a reason to
		// leave the box's reverse proxy on an old image. The two have nothing to
		// do with each other.
		ch <- runOutputMsg("")
		ch <- runOutputMsg("refreshing each app's scripts...")
		appErr := refreshBoxApps(t, chanProgress{ch}, func(script string, env map[string]string) error {
			return stream(ch, exec.Command("ssh", t.sshArgs(envPrefix(env)+"sh -s")...), script)
		})

		if proxyInstalled {
			ch <- runOutputMsg("")
			ch <- runOutputMsg("updating the shared reverse proxy...")
			pc := exec.Command("ssh", t.sshArgs(envPrefix(proxyEnv(proxyOpts{
				network: net, image: img, tlsAsk: tlsAsk,
			}))+"sh -s")...)
			if err := stream(ch, pc, scripts.AlpineProxyScript); err != nil {
				ch <- runDoneMsg{err: errors.Join(appErr,
					fmt.Errorf("the server updated, but the proxy step failed -- press p to retry it"))}
				return
			}
		}
		ch <- runDoneMsg{err: appErr}
	}()
	return m.run.wait()
}
