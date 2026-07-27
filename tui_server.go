package main

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// One page for the box itself: Docker, the shared network, and the proxy.
//
// They were three screens once, which was three keys to remember for what is
// really one question -- is this server healthy, and can it reach my apps? The
// answer is spread across all three: the proxy can be up while an app is not on
// the network, or on it under an alias another app already answers to. Split
// across screens, nobody correlates them.

const proxyProject = "ncicd-proxy"

// proxyCompose is the prefix for acting on the proxy stack. Pinned to the
// project name rather than the directory, because a compose project cannot be
// named after a directory beginning with an underscore.
func proxyCompose(verb string) string {
	return fmt.Sprintf("docker compose -f %s/compose.yml -p %s %s", proxyDir, proxyProject, verb)
}

type proxyLogsMsg struct {
	lines string
	err   error
}

// fetchProxyLogs pulls the tail of the proxy's own log. Caddy records its
// certificate work there, so it is usually the answer to "why is my domain not
// serving".
func fetchProxyLogs(t target) tea.Cmd {
	return func() tea.Msg {
		out, err := t.quiet("docker logs --tail 40 " + proxyContainer + " 2>&1")
		if err != nil && strings.TrimSpace(out) == "" {
			return proxyLogsMsg{err: fmt.Errorf("could not read the proxy's log -- is it created yet?")}
		}
		return proxyLogsMsg{lines: out}
	}
}

// startProxyAction runs one lifecycle command against the proxy stack.
func (m model) startProxyAction(verb, title string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		c := exec.Command("ssh", t.sshArgs("sh -s")...)
		// `up -d` rather than `start` for the start case: start fails on a
		// container that was removed rather than stopped, and recreating it is
		// what someone pressing "start" means either way.
		if err := stream(ch, c, "set -e\ncd "+proxyDir+"\n"+proxyCompose(verb)+"\n"); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("could not %s the proxy -- see the output above", title)}
			return
		}
		ch <- runDoneMsg{}
	}()
	return m.run.wait()
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

func (m model) handleServerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "left", "h":
		m.scr = screenList
		m.proxyLogs = ""
		return m, nil

	case "s":
		// Settings are the proxy's network and image; there is nothing else on
		// the box that is a setting rather than a fact.
		m.proxyForm = newProxyForm()
		if m.proxy.installed {
			m.proxyForm.set(m.proxy)
		}
		m.scr = screenProxyForm
		return m, nil

	case "l":
		if !m.proxy.installed {
			return m, nil
		}
		m.proxyLogs = "loading…"
		return m, fetchProxyLogs(m.tgt)

	case "t":
		if !m.proxy.installed {
			return m, nil
		}
		// One key for both directions: the label says which it will do, and
		// separate start/stop keys means hitting the wrong one.
		if m.proxy.running() {
			m.confirm = confirmPrompt{
				title: "Stop the reverse proxy?",
				body: []string{
					"EVERY app on this box stops being reachable — this is the one",
					"container they all depend on. Containers keep running; nothing",
					"is deleted, and certificates are untouched.",
					"",
					"Press t again on this screen to bring it back.",
				},
				action: func(m *model) tea.Cmd { return m.startProxyAction("stop", "stop") },
			}
			m.scr = screenConfirm
			return m, nil
		}
		m.scr = screenRunning
		m.run = newRunState("Starting the reverse proxy")
		return m, m.startProxyAction("up -d", "start")

	case "r":
		if !m.proxy.installed {
			return m, nil
		}
		m.scr = screenRunning
		m.run = newRunState("Restarting the reverse proxy")
		return m, m.startProxyAction("restart", "restart")

	case "u":
		m.confirm = confirmPrompt{
			title: "Re-run server setup on " + m.tgt.host + "?",
			body: []string{
				"Installs any Docker updates and makes sure the '" + defaultNetwork + "' network exists.",
				"",
				"Your apps keep running, and the reverse proxy is not touched —",
				"press t or r for that. Nothing is deleted.",
			},
			action: func(m *model) tea.Cmd { return m.startServerUpdate() },
		}
		m.scr = screenConfirm
		return m, nil

	case "R":
		m.scr = screenLoading
		return m, fetchApps(m.tgt)
	}
	return m, nil
}

func (m model) viewServer() string {
	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render("Server") + "\n")

	b.WriteString(section("the box"))
	b.WriteString(kv("docker", orDash(m.srv.docker)))
	b.WriteString(kv("network", m.networkLine()))
	b.WriteString(kv("proxy", m.proxyLine()))
	b.WriteString(kv("certs", dimStyle.Render(proxyProject+"_caddy_data (volume)")))

	b.WriteString(m.attachedSection())
	b.WriteString(m.problemsSection())

	if m.proxyLogs != "" {
		b.WriteString(section("proxy log"))
		lines := strings.Split(strings.TrimRight(m.proxyLogs, "\n"), "\n")
		if max := m.height - 28; max > 3 && len(lines) > max {
			lines = lines[len(lines)-max:]
		}
		for _, l := range lines {
			b.WriteString(gutter + "  " + dimStyle.Render(l) + "\n")
		}
	}

	if !m.proxy.installed {
		b.WriteString(help("s", "install a proxy", "u", "update server", "R", "refresh", "esc", "back"))
		return b.String()
	}
	toggle := "stop proxy"
	if !m.proxy.running() {
		toggle = "start proxy"
	}
	b.WriteString(help("t", toggle, "r", "restart", "l", "logs",
		"s", "settings", "u", "update server", "esc", "back"))
	return b.String()
}

func (m model) networkLine() string {
	n := m.net
	if n.name == "" {
		return dot("err") + " " + errStyle.Render("none") +
			dimStyle.Render(" — apps cannot reach each other · press u")
	}
	meta := n.driver
	if n.subnet != "" {
		meta += ", " + n.subnet
	}
	return dot("ok") + " " + n.name + dimStyle.Render("  "+meta)
}

func (m model) proxyLine() string {
	p := m.proxy
	switch {
	case !p.installed:
		return dot("") + dimStyle.Render(" not installed — apps publish their own ports · press s")
	case !p.running():
		return dot("err") + " " + errStyle.Render("stopped") +
			dimStyle.Render("  "+p.status+" · "+p.image)
	default:
		return dot("ok") + " running" + dimStyle.Render("  "+p.status+" · "+p.image)
	}
}

// attachedSection is the part that is invisible everywhere else: which
// containers are actually on the shared network, and under what name the proxy
// would reach them by.
func (m model) attachedSection() string {
	var b strings.Builder
	if m.net.name == "" {
		return ""
	}
	dupes := m.net.duplicateAliases()

	b.WriteString(section("on " + m.net.name))
	if len(m.net.members) == 0 {
		b.WriteString(gutter + "  " + dimStyle.Render("nothing is attached yet") + "\n")
		return b.String()
	}
	members := append([]netMember(nil), m.net.members...)
	sort.Slice(members, func(i, j int) bool { return members[i].container < members[j].container })

	rows := [][]string{{"CONTAINER", "REACHABLE AS", ""}}
	for _, mem := range members {
		var shown []string
		clash := false
		for _, a := range mem.aliases {
			if _, dup := dupes[a]; dup {
				shown = append(shown, errStyle.Render(a))
				clash = true
			} else {
				shown = append(shown, a)
			}
		}
		flag := ""
		if clash {
			flag = errStyle.Render("clash")
		}
		rows = append(rows, []string{
			dimStyle.Render(mem.container),
			strings.Join(shown, dimStyle.Render(", ")),
			flag,
		})
	}
	b.WriteString(table(rows, -1))
	return b.String()
}

// problemsSection collects everything that would produce a 502 while every
// other indicator on the box looks healthy.
func (m model) problemsSection() string {
	var b strings.Builder
	dupes := m.net.duplicateAliases()

	var missing []string
	for _, a := range m.apps {
		if a.routes == "" {
			continue
		}
		found := false
		for _, mem := range m.net.members {
			if strings.HasPrefix(mem.container, a.name) {
				found = true
			}
			for _, al := range mem.aliases {
				if strings.HasPrefix(al, a.name) {
					found = true
				}
			}
		}
		if !found {
			missing = append(missing, a.name)
		}
	}

	if len(dupes) > 0 {
		var names []string
		for a := range dupes {
			names = append(names, a)
		}
		sort.Strings(names)
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render("alias clash: "+strings.Join(names, ", ")) + "\n")
		b.WriteString(para(gutter+"  ", "More than one container answers to that name, so traffic to it\nis split between them at random. Compose gives every service an\nalias equal to its service name — give each app a unique one:"))
		b.WriteString(para(gutter+"    ", "\nnetworks:\n  shared:\n    aliases: [myapp-web]"))
	}

	if len(missing) > 0 {
		b.WriteString("\n" + gutter + dot("warn") + " " + warnStyle.Render(
			"publishing routes but not on this network: "+strings.Join(missing, ", ")) + "\n")
		b.WriteString(para(gutter+"  ", "The proxy has nothing to forward to, so those hostnames 502.\nAdd the network to each app's compose.yml and redeploy."))
	}

	if m.proxy.installed && !m.proxy.running() {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(
			"every app on this box is unreachable while the proxy is stopped") + "\n")
	}

	if len(dupes) == 0 && len(missing) == 0 && m.proxy.running() && len(m.net.members) > 0 {
		b.WriteString("\n" + gutter + dot("ok") + dimStyle.Render(" no problems") + "\n")
		b.WriteString(para(gutter+"  ", "The proxy is up, and every app publishing routes is attached\nunder a unique alias."))
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return dimStyle.Render("—")
	}
	return s
}
