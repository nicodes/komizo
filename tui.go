package main

import (
	"strings"
	"time"

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
	screenLoading screen = iota
	screenInit           // connected, but the server has nothing installed
	screenList           // the apps on this box
	screenAddForm        // name + config image for a new app
	screenLogs           // one log, full window
	screenRunning        // an operation is in flight, streaming output
	screenResult         // it finished; show what came back
)

type model struct {
	tgt    target
	scr    screen
	err    error
	status string // one-line note under the app list
	// statusErr distinguishes "known_hosts copied" from "no such container".
	// Both used to render green, which made a failed action look like it worked.
	statusErr bool

	apps  []appRow
	srv   serverRow
	proxy proxyRow
	net   netRow

	// cursor indexes focusItems(), not apps. The list is one column of things
	// you can act on -- the proxy, the known_hosts value, each app, each of its
	// containers -- so arrowing through it reaches everything on the page
	// rather than only the app rows.
	cursor int

	// busy is the rows with a lifecycle action in flight, so the spinner knows
	// which dots to animate and a second press cannot queue a second command.
	//
	// settling is the rows whose action has finished but whose new state has
	// not arrived yet. They keep spinning, and that is the whole point: the
	// inventory is only re-read after the command returns, so for one frame in
	// between the model still holds the OLD state. Clearing the spinner there
	// made stopping something read green -> spinner -> green -> red, with a
	// flash of the state you had just left.
	busy     map[string]bool
	settling map[string]bool
	spin     int

	// loaded records that the first inventory has arrived, so the cursor can be
	// parked on the first app once and not re-parked on every refresh.
	loaded bool

	form addForm

	// prompt is the question in the footer, if one is being asked. Nil most of
	// the time; the list stays on screen behind it either way.
	prompt *prompt

	// The log window: what is showing, whose it is, what to call it, how to
	// fetch it again, and how far down you have scrolled.
	logs      string
	logsOf    string // container name, so a late fetch for another one is dropped
	logsLabel string
	logsCmd   string
	logScroll int
	logsReady bool // the fetch has come back, even if it came back empty
	run       runState

	width, height int
}

func newModel(t target) model {
	return model{tgt: t, scr: screenLoading, form: newAddForm(t)}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(fetchApps(m.tgt), tea.WindowSize(), clockTick())
}

// clockMsg is one second passing.
//
// Every duration on the page is computed at render time from a timestamp the
// box already gave us, so keeping them current costs nothing but a repaint --
// no SSH, no inventory, no work on the server at all. Without it the numbers
// would simply be as old as the last keypress, which on a page you leave open
// to watch something is most of the time.
//
// Every ten seconds. Nothing here is shown finer than a minute, so a
// once-a-second repaint would be redrawing an identical screen nine times out
// of ten -- but a full minute between ticks would leave a value up to a minute
// stale, which on the row you just acted on is the one place it shows.
type clockMsg struct{}

func clockTick() tea.Cmd {
	return tea.Tick(10*time.Second, func(time.Time) tea.Msg { return clockMsg{} })
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
		// This snapshot covers every row, so anything waiting on one is now
		// current. Rows still mid-command keep their own spinner via busy.
		m.settling = nil
		if !m.loaded {
			// Start on the first app. The box rows come first on the page and
			// are a few presses of up away, but the apps are what people open
			// this to look at.
			m.loaded = true
			m.cursor = m.firstAppRow()
		}
		if n := len(m.focusItems()); m.cursor >= n {
			m.cursor = max(0, n-1)
		}
		// A box with nothing installed gets its own screen rather than an empty
		// app list, which would look identical to a set-up server with no apps.
		if m.err == nil && !m.srv.ready() {
			m.scr = screenInit
			return m, nil
		}
		m.scr = screenList
		return m, nil

	case clockMsg:
		// Nothing to change: the view reads the clock itself. Returning at all
		// is what triggers the repaint.
		return m, clockTick()

	case spinMsg:
		if !m.spinning() {
			return m, nil // nothing left to animate; let the ticker die
		}
		m.spin++
		return m, spinTick()

	case opDoneMsg:
		delete(m.busy, msg.key)
		if msg.err != nil {
			m.status, m.statusErr = msg.err.Error(), true
			return m, nil
		}
		// Keep spinning until the refreshed inventory lands. Re-reading rather
		// than guessing is deliberate -- a stop that half-worked should show as
		// half-worked -- but it means the truth arrives a moment after the
		// command does, and the row must not claim to know anything in between.
		if m.settling == nil {
			m.settling = map[string]bool{}
		}
		m.settling[msg.key] = true
		return m, fetchApps(m.tgt)

	case runOutputMsg:
		m.run.append(string(msg))
		return m, m.run.wait()

	case logsMsg:
		// Ignored if another log was asked for while this was in flight --
		// otherwise a slow fetch overwrites the one you asked for second.
		if msg.container != m.logsOf {
			return m, nil
		}
		m.logsReady = true
		if msg.err != nil {
			m.logs = msg.err.Error()
		} else {
			m.logs = msg.lines
		}
		// A log arriving is a new document, not a continuation of the last one.
		if m.logScroll > m.maxLogScroll() {
			m.logScroll = m.maxLogScroll()
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
	// A question in the footer takes the keys while it is open, whatever screen
	// is behind it -- otherwise typing an app's name to confirm its removal
	// would also be pressing the keys that act on it.
	if m.prompt != nil && m.scr == screenList {
		return m.handlePromptKey(msg)
	}

	switch m.scr {
	case screenList:
		return m.handleListKey(msg)
	case screenLogs:
		return m.handleLogsKey(msg)
	case screenInit:
		return m.handleInitKey(msg)
	case screenAddForm:
		return m.handleFormKey(msg)
	case screenResult:
		switch msg.String() {
		case "up", "k":
			if m.run.result != nil && m.run.result.cursor > 0 {
				m.run.result.cursor--
			}
			return m, nil
		case "down", "j":
			if m.run.result != nil && m.run.result.cursor < m.run.result.items()-1 {
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

// What the cursor can land on. One flat list, in the order the page draws it.
type focusKind int

const (
	focusServer    focusKind = iota // the box itself: docker and the network
	focusHosts                      // the SSH_KNOWN_HOSTS value
	focusProxy                      // the shared reverse proxy
	focusApp                        // one app
	focusContainer                  // one container belonging to an app
)

type focusItem struct {
	kind focusKind
	app  int // index into m.apps, or -1
	ctr  int // index into m.apps[app].containers, or -1
}

// focusItems is every row the cursor can reach, in display order.
//
// Built in one place and used by both the view and the key handling, so the
// highlight and what a keypress acts on cannot disagree -- which they will, the
// first time a row is added to one and not the other.
//
// Rows that are pure output are deliberately absent: a route nothing answers to
// is a diagnosis, not a thing you can do something to, and stopping on it would
// mean pressing down twice for no reason.
func (m model) focusItems() []focusItem {
	var out []focusItem
	// In page order. Every row that has something to do sits in this list, and
	// the ones that are pure fact do not -- which is why the docker row is here
	// (enter re-runs setup on it) and the network row is not.
	out = append(out, focusItem{kind: focusServer, app: -1, ctr: -1})
	if len(m.srv.hostKeys) > 0 {
		out = append(out, focusItem{kind: focusHosts, app: -1, ctr: -1})
	}
	if m.proxy.installed {
		out = append(out, focusItem{kind: focusProxy, app: -1, ctr: -1})
	}
	for i, a := range m.apps {
		out = append(out, focusItem{kind: focusApp, app: i, ctr: -1})
		for j := range a.containers {
			out = append(out, focusItem{kind: focusContainer, app: i, ctr: j})
		}
	}
	return out
}

// firstAppRow is where the app rows begin, or 0 on a box with none.
func (m model) firstAppRow() int {
	for i, f := range m.focusItems() {
		if f.kind == focusApp {
			return i
		}
	}
	return 0
}

// focused is what the cursor is on. The zero value is safe: an empty box has
// nothing to focus, and every caller checks the kind before using the indices.
func (m model) focused() focusItem {
	items := m.focusItems()
	if m.cursor < 0 || m.cursor >= len(items) {
		return focusItem{kind: focusApp, app: -1, ctr: -1}
	}
	return items[m.cursor]
}

// selectedApp is the app the cursor is ON, and only that.
//
// A container row deliberately does not count. Removing and rotating are
// app-wide, and offering them from a row that names one container invites
// exactly the wrong reading: that "remove" removes the container you are
// looking at. Arrowing up to the app is one keypress and makes the target
// unambiguous, which is worth more than the keypress.
func (m model) selectedApp() int {
	if f := m.focused(); f.kind == focusApp {
		return f.app
	}
	return -1
}

// focusedContainer is the container under the cursor, or nil.
func (m model) focusedContainer() *containerRow {
	f := m.focused()
	if f.kind != focusContainer {
		return nil
	}
	return &m.apps[f.app].containers[f.ctr]
}

// handleListKey drives the one screen there is.
//
// The box used to have a page of its own, reached with "s". It is now the block
// above the app list, because the two were never separable questions: "is my
// app up" and "can anything reach it" have the same answer most of the time,
// and splitting them meant the proxy could be stopped for as long as it took
// someone to think of pressing s. State you must navigate to is state you find
// out about late.
//
// The cost is that the server's actions moved onto keys the list had spare, so
// "l" and "h" no longer duplicate enter and esc. They were aliases for keys
// that already existed; the proxy's log had nowhere else to go.
func (m model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.focusItems())-1 {
			m.cursor++
		}

	case "enter":
		// Enter is the primary action on whatever is selected. For the three
		// things that RUN -- the proxy, an app, a container -- that is starting
		// or stopping it, in the direction it is not currently in.
		//
		// One key for both directions, and the hint says which way it will go.
		// Separate start and stop keys means eventually pressing the wrong one,
		// and the wrong one here takes something off the internet.
		return m.primaryAction()

	case "c":
		// Changing which image the host trusts for its config. Re-running setup
		// is what applies it; this is the same operation, named after what you
		// are actually doing rather than hidden behind "add".
		if i := m.selectedApp(); i >= 0 {
			m = m.ask(m.configPrompt(m.apps[i]))
		}

	case "a":
		// Global, unlike the other app keys. Adding does not act on a selection
		// -- there is nothing to select yet -- and it is the thing done most
		// often, so making it depend on where the cursor happens to be would be
		// a gate around the common case.
		m.form = newAddForm(m.tgt)
		m.scr = screenAddForm
	case "r":
		if i := m.selectedApp(); i >= 0 {
			m = m.ask(m.rotatePrompt(m.apps[i]))
		}
	case "x":
		if i := m.selectedApp(); i >= 0 {
			m = m.ask(m.removePrompt(m.apps[i]))
		}

	// --- the box ------------------------------------------------------------

	case "l":
		// Logs of whatever is selected, for the three things that run. Rows
		// that are not one of those do not offer it, and do not silently fall
		// back to something else's log either -- an unadvertised key that acts
		// on a row you did not select is worse than no key.
		switch f := m.focused(); f.kind {
		case focusProxy:
			return m.openLogs(proxyContainer, "proxy", containerLogCmd(proxyContainer))
		case focusContainer:
			c := m.focusedContainer()
			return m.openLogs(c.name, c.service, containerLogCmd(c.name))
		case focusApp:
			if f.app < 0 {
				return m, nil
			}
			a := m.apps[f.app]
			return m.openLogs("app:"+a.name, a.name, stackLogCmd(a))
		}
		return m, nil
	case "p":
		// Installs the proxy, or reinstalls it in place. Re-running is how you
		// pick up a newer Caddy, and it is not destructive: the certificate
		// volume outlives the container.
		//
		// It carries the box's CURRENT network and image forward rather than
		// asking. There was a form here once with those two fields, and it was
		// two questions to reach a button that almost always wanted the values
		// already on screen. Changing either is rare enough to belong on the
		// command line, where it is one flag: komizo proxy --network / --image.
		m = m.ask(m.installProxyPrompt())

	case "R":
		m.scr = screenLoading
		m.status, m.statusErr = "", false
		m.logs, m.logsOf = "", ""
		return m, fetchApps(m.tgt)
	}
	return m, nil
}

// copyKnownHosts puts the value CI pins on the clipboard.
//
// Reached by selecting the row and pressing enter. It had a global "y" as well,
// which was a second route to something already offered on the row it belongs
// to -- the same redundancy "t" and "u" had before it. Not a secret -- it
// needs integrity, not secrecy -- so it is copied like any other text.
func (m model) copyKnownHosts() model {
	if len(m.srv.hostKeys) == 0 {
		return m
	}
	if err := copyToClipboard(formatKnownHosts(m.tgt, m.srv.hostKeys) + "\n"); err != nil {
		m.status, m.statusErr = err.Error(), true
	} else {
		m.status, m.statusErr = "known_hosts copied", false
	}
	return m
}

// openLogs gives a log the whole window.
//
// Always a fresh fetch, and always from the top. Reopening the same log after
// something has happened to it is the common case, and showing yesterday's
// scroll position in yesterday's text would be worse than a moment's wait.
func (m model) openLogs(key, label, cmd string) (tea.Model, tea.Cmd) {
	m.logs, m.logsOf, m.logsLabel, m.logsCmd = "", key, label, cmd
	m.logsReady, m.logScroll = false, 0
	m.status, m.statusErr = "", false
	wasSpinning := m.spinning()
	m.scr = screenLogs
	cmds := []tea.Cmd{fetchLogs(m.tgt, key, cmd)}
	if !wasSpinning {
		cmds = append(cmds, spinTick())
	}
	return m, tea.Batch(cmds...)
}

// primaryAction is what enter does, by row.
//
// Every action reachable from this page is here or on a key that has nowhere
// else to live. Updating the server had a global "u" as well as this, which is
// two ways to do one thing and one of them redundant -- the docker row is where
// the version it changes is displayed, so that is where it belongs.
//
// Stopping asks first; starting does not. The asymmetry is the point: starting
// something that is already meant to be running is recoverable by definition,
// and stopping takes a service off the internet.
func (m model) primaryAction() (tea.Model, tea.Cmd) {
	switch f := m.focused(); f.kind {
	case focusServer:
		m = m.ask(m.updateServerPrompt())
		return m, nil

	case focusHosts:
		return m.copyKnownHosts(), nil

	case focusProxy:
		return m.ask(m.lifecyclePrompt(
			title(startStop(m.proxy.running()))+" the proxy?",
			"Every app on this box stops being reachable while it is down. "+
				"Containers keep running and certificates are untouched.",
			proxyContainer, proxyCompose(verbFor(m.proxy.running())))), nil

	case focusApp:
		if f.app < 0 {
			return m, nil
		}
		a := m.apps[f.app]
		detail := "Nothing is deleted — the directory, the volumes and the secrets stay."
		if a.up() {
			if hosts := a.allRoutes(); len(hosts) > 0 {
				detail = "These stop answering: " + strings.Join(hosts, ", ") + ". " + detail
			}
		}
		// `up -d` rather than `start`: a container that was removed rather than
		// stopped cannot be started, and recreating it is what start means.
		return m.ask(m.lifecyclePrompt(
			title(startStop(a.up()))+" "+a.name+"?", detail,
			"app:"+a.name, stackCmd(a, verbFor(a.up())))), nil

	case focusContainer:
		c := m.focusedContainer()
		detail := "The rest of " + c.app + " is unaffected, and nothing is deleted."
		if hosts := m.routesFor(*c); c.up() && len(hosts) > 0 {
			detail = "These stop answering: " + strings.Join(hosts, ", ") + ". " + detail
		}
		return m.ask(m.lifecyclePrompt(
			title(startStop(c.up()))+" "+c.service+"?", detail,
			c.name, containerCmd(c.name, plainVerb(c.up())))), nil
	}
	return m, nil
}

// lifecyclePrompt asks before starting or stopping something.
//
// These ran without asking for a while, on the reasoning that pressing the same
// key again undoes them. True of the mechanism, not of the consequence: the gap
// between stopping something and noticing is however long it takes to look, and
// in that gap a domain is 502ing. So the question names the hostnames that go
// quiet -- the one fact that makes the answer obvious, and the one you cannot
// work out from the row you are on.
func (m model) lifecyclePrompt(q, detail, key, cmd string) prompt {
	return prompt{
		question: q,
		detail:   detail,
		action: func(m *model, _ string) tea.Cmd {
			return m.begin(key, cmd)
		},
	}
}

// verbFor is the compose verb that reverses the current state.
func verbFor(running bool) string {
	if running {
		return "stop"
	}
	return "up -d"
}

// plainVerb is the same for a bare container, which has no compose project to
// recreate it from.
func plainVerb(running bool) string {
	if running {
		return "stop"
	}
	return "start"
}

// begin marks a row busy and performs its action in the background.
//
// A pointer receiver, and that is load-bearing. On a value receiver the first
// call would allocate the busy map on its own copy and lose it, so the very
// first action of a session would run without ever showing a spinner -- and
// then work correctly forever after, which is the worst way for a bug to
// behave.
func (m *model) begin(key, cmd string) tea.Cmd {
	if m.busy[key] {
		return nil // already in flight; a second press must not queue another
	}
	// One ticker, however many rows are moving. Decided before the row is
	// marked, because "was anything already spinning" is the question -- start
	// a second and the animation runs at double speed.
	wasSpinning := m.spinning()
	if m.busy == nil {
		m.busy = map[string]bool{}
	}
	m.busy[key] = true
	m.status, m.statusErr = "", false
	cmds := []tea.Cmd{runOp(m.tgt, key, cmd)}
	if !wasSpinning {
		cmds = append(cmds, spinTick())
	}
	return tea.Batch(cmds...)
}

// spinning reports whether any row is mid-action or waiting for the refresh
// that follows one.
func (m model) spinning() bool {
	return len(m.busy)+len(m.settling) > 0 || (m.scr == screenLogs && m.loading())
}

// routesFor is the hostnames that reach one container, for the moment before
// you take it down.
func (m model) routesFor(c containerRow) []string {
	for _, a := range m.apps {
		if a.name != c.app {
			continue
		}
		byContainer := a.routesByContainer(m.net)
		return byContainer[c.name]
	}
	return nil
}

// installProxyPrompt reinstalls the shared proxy with whatever the box is
// already using.
func (m model) installProxyPrompt() prompt {
	o := proxyOpts{network: m.net.name, image: m.proxy.image}
	if o.network == "" {
		o.network = defaultNetwork
	}
	if o.image == "" {
		o.image = defaultProxy
	}
	q := "Reinstall the proxy from " + o.image + "?"
	detail := "Certificates survive — they are in a volume. Every app is briefly unreachable."
	if !m.proxy.installed {
		q = "Install the proxy from " + o.image + " on '" + o.network + "'?"
		detail = "One Caddy terminates HTTPS for every app, so no app publishes a port."
	}
	return prompt{
		question: q,
		detail:   detail,
		action: func(m *model, _ string) tea.Cmd {
			m.scr = screenRunning
			m.run = newRunState(q)
			return m.startProxy(o)
		},
	}
}

func (m model) updateServerPrompt() prompt {
	q := "Re-run server setup on " + m.tgt.host + "?"
	return prompt{
		question: q,
		detail: "Installs any Docker updates. Your apps keep running, the proxy is not " +
			"touched either way, and nothing is deleted.",
		action: func(m *model, _ string) tea.Cmd {
			m.scr = screenRunning
			m.run = newRunState(q)
			return m.startServerUpdate()
		},
	}
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(header())

	switch m.scr {
	case screenLoading:
		b.WriteString("\n" + gutter + barStyle.Render("▍") + dimStyle.Render(" connecting…") + "\n")
	case screenList:
		b.WriteString(viewList(m))
	case screenLogs:
		b.WriteString(m.viewLogs())
	case screenInit:
		b.WriteString(viewInit(m.srv))
	case screenAddForm:
		b.WriteString(m.form.view())
	case screenRunning, screenResult:
		b.WriteString(m.run.view(m.scr == screenResult, m.height))
	}

	if m.err != nil {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(m.err.Error()) + "\n")
	}

	out := trimTrailing(b.String())
	// The list and the log window pin their footers. The others are a question
	// or a stream of output, and padding those to the bottom of the terminal
	// would leave the thing you are reading floating at the top.
	switch m.scr {
	case screenList:
		return out + m.pad(out, m.footer()) + trimTrailing(m.footer())
	case screenLogs:
		f := m.logsFooter()
		return out + m.pad(out, f) + trimTrailing(f)
	}
	return out
}

// pad is the blank space that pushes the footer to the bottom of the terminal.
//
// Nothing at all when the content already overflows: pinning is a nicety, and
// scrolling the top of the page off to honour it would trade a fixed position
// for the information you came to read.
func (m model) pad(body, footer string) string {
	if m.height <= 0 {
		return ""
	}
	used := strings.Count(body, "\n") + strings.Count(footer, "\n") + 2
	if used >= m.height {
		return ""
	}
	return strings.Repeat("\n", m.height-used)
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
