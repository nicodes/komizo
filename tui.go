package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// The TUI is the primary interface: `ncicd root@host` connects and everything
// is done from there. The flag-driven subcommands remain for scripting, but a
// person setting up a box should not have to learn them.
//
// Every operation that touches the server runs as a tea.Cmd returning a
// message, so the interface never blocks while an apk install runs.

type screen int

const (
	screenLoading   screen = iota
	screenInit             // connected, but the server has nothing installed
	screenList             // the apps on this box
	screenDetail           // one app
	screenAddForm          // name + config image for a new app
	screenServer           // the box: docker, network, proxy, and what is wrong
	screenProxyForm        // network and image for the shared reverse proxy
	screenConfirm          // destructive action, spelled out
	screenRunning          // an operation is in flight, streaming output
	screenResult           // it finished; show what came back
)

type model struct {
	tgt    target
	scr    screen
	err    error
	status string // one-line note under the header

	apps   []appRow
	srv    serverRow
	proxy  proxyRow
	net    netRow
	cursor int

	form      addForm
	proxyForm proxyFormModel
	initForm  initForm
	proxyLogs string
	confirm   confirmPrompt
	run       runState

	width, height int
}

func newModel(t target) model {
	return model{tgt: t, scr: screenLoading, form: newAddForm(),
		proxyForm: newProxyForm(), initForm: newInitForm()}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(fetchApps(m.tgt), tea.WindowSize())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		// Ctrl+C always leaves, whatever is on screen -- except mid-operation,
		// where quitting would abandon a half-applied change on the server.
		if msg.String() == "ctrl+c" && m.scr != screenRunning {
			return m, tea.Quit
		}
		return m.handleKey(msg)

	case appsMsg:
		m.apps, m.srv, m.proxy, m.net, m.err = msg.apps, msg.srv, msg.proxy, msg.net, msg.err
		if m.cursor >= len(m.apps) {
			m.cursor = max(0, len(m.apps)-1)
		}
		// A box with nothing installed gets its own screen rather than an empty
		// app list, which would look identical to a set-up server with no apps.
		if m.err == nil && !m.srv.ready() {
			m.initForm = newInitForm()
			m.scr = screenInit
			return m, nil
		}
		m.scr = screenList
		return m, nil

	case runOutputMsg:
		m.run.append(string(msg))
		return m, m.run.wait()

	case proxyLogsMsg:
		if msg.err != nil {
			m.proxyLogs = msg.err.Error()
		} else {
			m.proxyLogs = msg.lines
		}
		return m, nil

	case runDoneMsg:
		m.run.done = true
		m.run.err = msg.err
		m.run.result = msg.result
		m.scr = screenResult
		return m, nil
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.scr {
	case screenList:
		return m.handleListKey(msg)
	case screenDetail:
		switch msg.String() {
		case "esc", "q", "left", "h":
			m.scr = screenList
		}
		return m, nil
	case screenInit:
		return m.handleInitKey(msg)
	case screenServer:
		return m.handleServerKey(msg)
	case screenAddForm:
		return m.handleFormKey(msg)
	case screenProxyForm:
		return m.handleProxyFormKey(msg)
	case screenConfirm:
		return m.handleConfirmKey(msg)
	case screenResult:
		switch msg.String() {
		case "esc", "q", "enter":
			m.scr = screenLoading
			m.status = ""
			return m, fetchApps(m.tgt)
		}
		return m, nil
	}
	return m, nil
}

func (m model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.apps)-1 {
			m.cursor++
		}
	case "enter", "right", "l":
		if len(m.apps) > 0 {
			m.scr = screenDetail
		}
	case "a":
		m.form = newAddForm()
		m.scr = screenAddForm
	case "r":
		if len(m.apps) > 0 {
			app := m.apps[m.cursor].name
			m.confirm = confirmPrompt{
				title: fmt.Sprintf("Rotate the deploy key for %q?", app),
				body: []string{
					"A new keypair is generated on this machine and installed on the server.",
					"",
					"The current key stops working immediately. Update SSH_DEPLOY_KEY in",
					"the repo's secrets before its next deploy, or that deploy will fail.",
				},
				confirmWord: "",
				action:      func(m *model) tea.Cmd { return m.startRotate(app) },
			}
			m.scr = screenConfirm
		}
	case "x":
		if len(m.apps) > 0 {
			a := m.apps[m.cursor]
			m.confirm = confirmPrompt{
				title: fmt.Sprintf("Remove %q from this server?", a.name),
				body: []string{
					"This stops its containers and deletes:",
					"  " + a.dir + " and its volumes",
					"  the account " + a.user + ", its doas rules and sshd restrictions",
					"  /usr/local/bin/deploy-" + a.name + " and set-secret-" + a.name,
					"",
					"Other apps on this box are untouched. Images stay in your registry.",
					"",
					"This cannot be undone.",
				},
				confirmWord: a.name,
				action:      func(m *model) tea.Cmd { return m.startRemove(a.name) },
			}
			m.scr = screenConfirm
		}
	case "s":
		// One key for the box itself. Docker, the network and the proxy were a
		// key each, which is three things to remember for what is really one
		// question: is this server healthy and can it reach my apps?
		m.proxyLogs = ""
		m.scr = screenServer
	case "R":
		m.scr = screenLoading
		return m, fetchApps(m.tgt)
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(header(m.tgt, m.width))

	switch m.scr {
	case screenLoading:
		b.WriteString("\n" + gutter + barStyle.Render("▍") + dimStyle.Render(" connecting…") + "\n")
	case screenList:
		b.WriteString(viewList(m))
	case screenDetail:
		b.WriteString(viewDetail(m))
	case screenInit:
		b.WriteString(m.initForm.view(m.srv))
	case screenServer:
		b.WriteString(m.viewServer())
	case screenAddForm:
		b.WriteString(m.form.view())
	case screenProxyForm:
		b.WriteString(m.proxyForm.view(m.proxy))
	case screenConfirm:
		b.WriteString(m.confirm.view())
	case screenRunning, screenResult:
		b.WriteString(m.run.view(m.scr == screenResult, m.height))
	}

	if m.err != nil {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(m.err.Error()) + "\n")
	}
	return trimTrailing(b.String())
}

func runTUI(hostArg string, port int, portExplicit bool) error {
	tgt, err := parseTarget(hostArg)
	if err != nil {
		return err
	}
	if err := validateHost(tgt.host); err != nil {
		return err
	}
	if portExplicit {
		tgt.port, tgt.portExplicit = port, true
	}
	// Without --port this reads the port out of the user's ssh config, so the
	// known_hosts lines we print match the port CI will actually connect on.
	tgt.resolvePort()

	if !tgt.reachable() {
		return fmt.Errorf("cannot SSH in as %s without a password.\n"+
			"    This needs an existing login to work from. If you normally type a\n"+
			"    password, run 'ssh-copy-id %s' first.", tgt.user, tgt.addr())
	}

	p := tea.NewProgram(newModel(tgt), tea.WithAltScreen())
	_, err = p.Run()
	return err
}
