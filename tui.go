package main

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// The TUI is the primary interface: `komizo root@host` connects and everything
// is done from there. The flag-driven subcommands remain for scripting, but a
// person setting up a box should not have to learn them.
//
// Every operation that touches the server runs as a tea.Cmd returning a
// message, so the interface never blocks while an apk install runs.

type screen int

const (
	screenLoading    screen = iota
	screenInit              // connected, but the server has nothing installed
	screenList              // the apps on this box
	screenDetail            // one app
	screenAddForm           // name + config image for a new app
	screenConfigForm        // change which config image an app trusts
	screenServer            // the box: docker, network, proxy, and what is wrong
	screenProxyForm         // network and image for the shared reverse proxy
	screenConfirm           // destructive action, spelled out
	screenRunning           // an operation is in flight, streaming output
	screenResult            // it finished; show what came back
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

	form       addForm
	configForm configForm
	proxyForm  proxyFormModel
	proxyLogs  string
	confirm    confirmPrompt
	run        runState

	width, height int
}

func newModel(t target) model {
	return model{tgt: t, scr: screenLoading, form: newAddForm(), proxyForm: newProxyForm()}
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
		if len(m.apps) == 0 {
			m.scr = screenList
			return m, nil
		}
		a := m.apps[m.cursor]
		switch msg.String() {
		case "esc", "q", "left", "h":
			m.scr = screenList
		case "c":
			// Changing which image the host trusts for its config. Re-running
			// setup is what applies it; this is the same operation, named after
			// what you are actually doing rather than hidden behind "add".
			m.configForm = newConfigForm(a)
			m.scr = screenConfigForm
		case "r":
			m.confirm = m.rotatePrompt(a)
			m.scr = screenConfirm
		case "x":
			m.confirm = m.removePrompt(a)
			m.scr = screenConfirm
		}
		return m, nil
	case screenConfigForm:
		return m.handleConfigFormKey(msg)
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
		case "up", "k":
			if m.run.result != nil && m.run.result.cursor > 0 {
				m.run.result.cursor--
			}
			return m, nil
		case "down", "j":
			if m.run.result != nil && m.run.result.cursor < resultItems-1 {
				m.run.result.cursor++
			}
			return m, nil
		case "c":
			// Both values have to reach GitHub, so both are copyable. Copying
			// one does not finish the job, which is why each keeps its own tick.
			if m.run.result == nil {
				return m, nil
			}
			if err := m.run.result.copySelected(); err != nil {
				m.run.result.copyErr = err.Error()
				m.run.result.onClipboard = -1
			} else {
				// Replaces, never accumulates: whatever was there is gone.
				m.run.result.onClipboard = m.run.result.cursor
				m.run.result.copyErr = ""
			}
			return m, nil
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
			m.confirm = m.rotatePrompt(m.apps[m.cursor])
			m.scr = screenConfirm
		}
	case "x":
		if len(m.apps) > 0 {
			m.confirm = m.removePrompt(m.apps[m.cursor])
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
		b.WriteString(viewInit(m.srv))
	case screenServer:
		b.WriteString(m.viewServer())
	case screenAddForm:
		b.WriteString(m.form.view())
	case screenConfigForm:
		b.WriteString(m.configForm.view())
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

func runTUI(hostArg string, port int, portExplicit bool, assumeYes bool) error {
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

	if r := tgt.probe(); !r.ok() {
		// A host nobody has met before is the normal state of a server you
		// just created, so deal with it here rather than sending someone away
		// to run ssh by hand and come back. It always asks first unless
		// --accept-host-key said not to.
		if r.kind == reachUnknownHost {
			if err := acceptHostKey(tgt, assumeYes); err != nil {
				return err
			}
			r = tgt.probe()
		}
		if !r.ok() {
			return r.explain(tgt)
		}
	}

	p := tea.NewProgram(newModel(tgt), tea.WithAltScreen())
	_, err = p.Run()
	return err
}
