package app

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	screenLogin screen = iota // no host given: ask which one
	screenLoading
	screenSetup   // connected, but the server has nothing installed
	screenIndex   // the apps on this box
	screenLogs    // one log, full window
	screenMonitor // requests over time, for the box, an app, or a container
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
	// parked on the first app once and not re-parked on every refresh. It is
	// also what tells a failed poll there is a good page to keep.
	loaded bool

	// fetching is a read already on its way, so the five-second poll cannot
	// stack connections on a box that is answering slower than it is asked.
	fetching bool

	// login is the address being typed on the login screen, and the reason
	// `komizo` with no arguments is a usable command rather than a usage error.
	login string

	// setupCancel is the cursor on the setup screen's two buttons. It starts on
	// start: someone who reached this screen connected to a server on purpose,
	// and defaulting to cancel would make the common case the extra keypress.
	setupCancel bool

	form addForm

	// prompt is the question in the footer, if one is being asked. Nil most of
	// the time; the list stays on screen behind it either way.
	prompt *prompt

	// The log window: what is showing, whose it is, what to call it, how to
	// fetch it again, and how far down you have scrolled.
	logs   string
	logsOf string // container name, so a late fetch for another one is dropped
	// What the log belongs to, for the breadcrumb: the app, and the container
	// within it when one was selected. The proxy has neither and names itself.
	logsLabel string // proxy, or the app; kept for the crumb's leaf
	logsApp   string // "" for the proxy
	logsSvc   string // "" for a whole app
	logsCmd   string
	logsBack  screen // where esc returns: logs open from the index and the monitor
	scroll    int
	logsReady bool // the fetch has come back, even if it came back empty
	run       runState

	// Request counts off the proxy's access log.
	//
	// metrics rides along on the inventory poll and covers a short window --
	// enough for the sparkline on an app's row. monitor is the deeper window the
	// monitor screen fetches for itself on entry, because reading hours of log
	// every five seconds to move a line one column is a waste of the box.
	metrics []metricRow
	monitor []metricRow

	// What the box and its containers are spending.
	//
	// sys is the last raw reading and sysHave says there has been one; sysPts
	// is the derived history, one point per PAIR of readings.
	//
	// The history lives here and nowhere else. Nothing on the box records it --
	// /proc reports now and only now -- so this covers the time komizo has been
	// connected and no further back, and is gone when it exits. That is a much
	// weaker claim than the request charts make, and the screen says so rather
	// than letting a chart imply otherwise.
	sys        sysSample
	sysHave    bool
	sysSamples []sysSample
	// sysLog is the same thing read back from the box, covering hours rather
	// than this session. Fetched with the monitor, because it is only ever
	// looked at there.
	sysLog []sysSample
	// vols is the app's disk use, fetched with the monitor because du is far
	// too expensive to put on a five-second poll.
	vols         []volRow
	monitorOf    string // which app, so a late fetch for another one is dropped
	monitorSvc   string // which container within it, or "" for the whole app
	monitorReady bool
	// span is how far back the proxy's access log reaches, reported with the
	// counts. What the charts can show is the range asked for narrowed to this.
	span    timeRange
	hasSpan bool
	// monitorRange is what the charts are looking at. Zero means the default,
	// which is the last few hours and is resolved fresh on every read -- a
	// default window has to still mean "the last four hours" after the page has
	// been open for twenty minutes, while a range somebody chose stays put.
	monitorRange timeRange

	// mouseOn is set while this interface is asking the terminal for mouse
	// events, which it does NOT do by default. See toggleMouse.
	mouseOn bool

	// freeScroll is set while the page is being driven by the wheel rather than
	// by the cursor. Cleared the moment a key moves the selection, so the two
	// never fight: the wheel moves the page, the arrows move the selection and
	// take the page with them.
	freeScroll bool

	// bodyRows is the page as reflow last rendered it, for View to slice.
	//
	// Rendering the body is by far the most expensive thing this program does
	// -- on the monitor it is a trailing median per point per panel and then
	// braille rasterisation for six charts, and a wide range makes that tens of
	// thousands of points -- and it was being done TWICE for every message:
	// once by reflow to find the cursor and count rows, then again by View to
	// draw it. Nothing between them can change it, because Update is the only
	// thing that changes state and reflow is the last thing Update does.
	//
	// Nil means nobody has reflowed yet, which is the first frame and any test
	// that renders a model straight off; View renders for itself there.
	bodyRows []string

	width, height int
}

func newModel(t target) model {
	return model{tgt: t, scr: screenLoading, form: newAddForm(t)}
}

// newLoginModel is `komizo` with nothing after it: no host to connect to, so
// the first thing on screen asks for one.
func newLoginModel() model {
	return model{scr: screenLogin, form: newAddForm(target{})}
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{tea.WindowSize(), pollTick()}
	// Nothing to read yet when there is no host: the login screen asks first,
	// and has nothing to animate until it gets an answer.
	if m.scr != screenLogin {
		cmds = append(cmds, m.fetch(), spinTick())
	}
	return tea.Batch(cmds...)
}

// beginLoading goes to the loading screen and makes sure something is driving
// the spinner.
//
// The ticker stops when nothing needs it -- spinMsg simply stops rescheduling
// itself -- so every path INTO a state that animates has to start it again.
// Deciding here, from whether anything was ALREADY spinning, is what keeps a
// second ticker from being spawned on top of a live one and running the
// animation at double speed.
//
// This is the bug it exists for: from the login screen nothing was spinning, so
// the first tick after startup killed the ticker, and connecting then showed a
// spinner frozen on its first frame. Started from the command line the model
// begins on the loading screen, where something IS spinning, so the identical
// code worked and the fault only appeared on the new path.
func (m *model) beginLoading(next tea.Cmd) tea.Cmd {
	return m.withSpin(func() { m.scr = screenLoading }, next)
}

// withSpin applies a state change and returns the commands that go with it,
// leaving exactly one ticker driving the animation.
//
// The change is passed IN rather than made by the caller, and that is the whole
// point. "Was anything already spinning" has to be asked before the change --
// ask it after and a screen that just marked itself not-ready reads as already
// spinning, so nothing is scheduled and the spinner freezes on one frame. Six
// places wrote that check by hand and two of them wrote it in the wrong order,
// which is a bug you cannot see in review because the correct and incorrect
// versions are the same three lines.
//
// Taking the change makes the wrong order unwritable, and asking again
// afterwards means a change that ends up needing no animation starts no ticker.
func (m *model) withSpin(change func(), cmds ...tea.Cmd) tea.Cmd {
	wasSpinning := m.spinning()
	change()
	if !wasSpinning && m.spinning() {
		cmds = append(cmds, spinTick())
	}
	return tea.Batch(cmds...)
}

// connectMsg is what a host turned out to be: reachable, never seen before, or
// unreachable with a reason.
type connectMsg struct {
	tgt  target
	res  reachResult
	scan []byte   // the host keys, when it is a host we have not met
	fp   []string // and their fingerprints, to compare before trusting them
}

// connect resolves the port the way the rest of the tool does -- out of the
// user's ssh config -- then finds out whether the host answers.
func connect(t target) tea.Cmd {
	return func() tea.Msg {
		t.resolvePort()
		r := t.probe()
		if r.kind != reachUnknownHost {
			return connectMsg{tgt: t, res: r}
		}
		// Scanned here rather than after the question, so the fingerprints are
		// on screen while it is being asked. Nothing has verified them; that is
		// what the question is for.
		scan, err := scanHostKeys(t)
		if err != nil {
			return connectMsg{tgt: t, res: reachResult{kind: reachOther, raw: err.Error()}}
		}
		return connectMsg{tgt: t, res: r, scan: scan, fp: fingerprints(scan)}
	}
}

// handleLoginKey drives the one field on the login screen.
func (m model) handleLoginKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "ctrl+c":
		return m, tea.Quit

	case "enter":
		host := strings.TrimSpace(m.login)
		if host == "" {
			return m, nil
		}
		t, err := parseTarget(host)
		if err == nil {
			err = validateHost(t.host)
		}
		if err != nil {
			m.status, m.statusErr = err.Error(), true
			return m, nil
		}
		// The spinner and the word take over while ssh is out; the field comes
		// back with its text intact if the host turns out not to answer.
		m.status, m.statusErr = "", false
		return m, m.beginLoading(connect(t))

	case "backspace":
		if m.login != "" {
			m.login = trimLastRune(m.login)
			m.status, m.statusErr = "", false
		}
		return m, nil
	}

	if s := typedText(msg); s != "" {
		m.login += s
		m.status, m.statusErr = "", false
	}
	return m, nil
}

// typedText is the text a keypress adds to a field: one character, or the whole
// of a paste.
//
// A paste arrives as ONE key message carrying every rune -- bracketed paste is
// on by default -- so the test this replaced, `len(msg.String()) == 1`, dropped
// it entirely. Every field in the interface was type-only, and silently: the
// keystroke was received and discarded, so nothing appeared and nothing said
// why. Pasting an address or a config image path is the normal way to enter
// one; they are copied from a provider's console or a registry page.
//
// Newlines, tabs and control characters are stripped rather than inserted.
// Every field here is a single line, and a value copied out of a terminal or a
// web page routinely brings a trailing newline with it.
//
// Alt chords are not text. Alt+a arrives as a rune with the Alt flag set, and
// inserting "a" for it would put a letter in the field for a key nobody typed.
// trimLastRune removes one CHARACTER from the end of a field, not one byte.
//
// Backspace used to slice a byte off, which is the same thing for everything
// typed on a keyboard and wrong for everything pasted: an internationalised
// hostname or a name with an accent in it would be cut mid-rune, leaving
// invalid UTF-8 that renders as a replacement character and then fails
// validation for a reason nothing on screen explains.
func trimLastRune(s string) string {
	if s == "" {
		return s
	}
	_, n := utf8.DecodeLastRuneInString(s)
	return s[:len(s)-n]
}

func typedText(msg tea.KeyMsg) string {
	if msg.Alt {
		return ""
	}
	switch msg.Type {
	case tea.KeySpace:
		return " "
	case tea.KeyRunes:
		var b strings.Builder
		for _, r := range msg.Runes {
			if !unicode.IsControl(r) {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return ""
}

// pollMsg is five seconds passing: time to re-read the box.
//
// It replaced a manual "R refresh" and a ten-second repaint that only redrew
// what was already in memory. Both were the same admission -- that the page
// could be wrong and you would not know -- and the second one made it worse by
// keeping the durations moving on a list that was otherwise frozen. A row can
// say a container has been up for nine minutes when it died eight minutes ago,
// and nothing on screen suggests asking.
//
// Five seconds is chosen for the case this page is open for: watching something
// you just changed settle, or watching for something that is about to go wrong.
//
// It is not free, and that is the trade. Every poll is a fresh SSH connection --
// no multiplexing here -- so a window left open all day is a login every five
// seconds in the server's auth log, and a handshake on both ends. Cheap for a
// box you are looking at, which is the only time this runs.
type pollMsg struct{}

// warmupMsg is the one-off second reading after the first sample lands, so the
// processor bar has its pair without waiting out a full poll interval.
type warmupMsg struct{}

// wheelRows is how far one notch moves the page. Three is the common default
// and reads as a nudge; one is imperceptible on a long page, and a screenful
// loses your place.
const wheelRows = 3

func pollTick() tea.Cmd {
	return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return pollMsg{} })
}

// poll re-reads the inventory, or does nothing.
//
// Three reasons to skip, and each is a way the poll could otherwise make the
// page worse than not polling at all:
//
//   - Not on the list. A refresh finishing while you are reading a log is an
//     answer to a question nobody asked, and appsMsg used to switch screens.
//   - One already in flight. A slow box would otherwise accumulate connections
//     faster than it answers them.
//   - A row is mid-action, or has just finished one and is waiting for the
//     truth to land. That refresh is already coming, and a poll landing in the
//     gap clears the spinner early -- the flicker `settling` exists to prevent.
//
// An open question is NOT one of them. It was, on the reasoning that a
// connection every five seconds while someone types an app name is work nobody
// asked for -- but the list behind the question is the reason the question is
// in the footer, and a list that stops updating the moment you start deciding
// is stale exactly when you are looking hardest. Nothing a poll returns can
// corrupt an answer: prompts capture the app they act on by value, and an
// operation in flight owns no rows.
func (m *model) poll() tea.Cmd {
	if m.scr != screenIndex || m.fetching || len(m.busy) > 0 || len(m.settling) > 0 {
		return nil
	}
	return m.fetch()
}

// fetch marks a read as in flight and returns the command that does it.
func (m *model) fetch() tea.Cmd {
	m.fetching = true
	return fetchApps(m.tgt)
}

// Update is the frame around the real one: whatever a message changes, the
// scroll offset is brought back into agreement with it before the next render.
//
// Here rather than in View because View is called on a copy -- a correction
// made there would be thrown away and recomputed from the stale value on every
// frame. See reflow.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	if nm, ok := next.(model); ok {
		nm.reflow()
		return nm, cmd
	}
	return next, cmd
}

func (m model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.MouseMsg:
		// The wheel moves the PAGE and never the selection. Scrolling to look
		// at something is not choosing it, and a wheel that moved the cursor
		// would arm every key in the footer against whatever drifted under it.
		switch msg.Type {
		case tea.MouseWheelUp:
			m.freeScroll = true
			m.scroll -= wheelRows
		case tea.MouseWheelDown:
			m.freeScroll = true
			m.scroll += wheelRows
		}
		return m, nil

	case tea.KeyMsg:
		// Ctrl+C always leaves, whatever is on screen -- except mid-operation,
		// where quitting would abandon a half-applied change on the server.
		if msg.String() == "ctrl+c" && !m.running() {
			return m, tea.Quit
		}
		// Selecting text works on every screen except the index, where s
		// starts and stops the selected row. Handled here rather than per
		// screen because the one you most want to copy from is the log
		// window, which has the fewest keys of its own.
		if msg.String() == "s" && m.scr != screenIndex && !m.running() && !m.typing() {
			return m.toggleMouse()
		}
		// Any key hands the page back to the cursor.
		m.freeScroll = false
		return m.handleKey(msg)

	case appsMsg:
		m.fetching = false

		// A poll that failed keeps the last good inventory on screen and says so
		// in the footer. Taking the assignment below would replace every row with
		// the empty slice that comes back with an error -- so one dropped
		// connection would blank a working page, and the next poll would put it
		// back. The first read is the exception: there is nothing to keep.
		if msg.err != nil {
			m.err = msg.err
			if m.loaded {
				return m, nil
			}
			m.scr = screenIndex
			return m, nil
		}

		m.apps, m.srv, m.proxy, m.net, m.err = msg.apps, msg.srv, msg.proxy, msg.net, nil
		m.metrics = msg.metrics
		m.takeSample(msg.sys)
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
		// Only ever from the loading screen. A poll landing while you are reading
		// a log, filling in the add form or watching a bootstrap must not move
		// you -- this used to set the screen unconditionally, which was harmless
		// when the only way here was pressing R on the list, and is not now that
		// one arrives every five seconds.
		//
		// A box with nothing installed gets its own screen rather than an empty
		// app list, which would look identical to a set-up server with no apps.
		if m.scr == screenLoading {
			if !m.srv.ready() {
				m.scr = screenSetup
			} else {
				m.scr = screenIndex
			}
		}
		// A processor rate needs a PAIR of readings, and this was the first:
		// one quick follow-up a second out, so the bar appears about when the
		// page does rather than a full poll interval later. Its own message,
		// not an early pollMsg -- pollMsg reschedules the ticker, and a second
		// chain of five-second ticks would poll the box twice as often forever.
		if len(m.sysSamples) == 1 {
			return m, tea.Tick(time.Second, func(time.Time) tea.Msg { return warmupMsg{} })
		}
		return m, nil

	case warmupMsg:
		return m, m.poll()

	case pollMsg:
		// The tick is rescheduled whatever else happens, so a screen that skips
		// the read does not stop the clock: come back to the list and the next
		// poll is five seconds away, not never.
		return m, tea.Batch(pollTick(), m.poll())

	case spinMsg:
		if !m.spinning() {
			return m, nil // nothing left to animate; let the ticker die
		}
		m.spin++
		return m, spinTick()

	case opDoneMsg:
		delete(m.busy, msg.key)
		if msg.err != nil {
			// scrub: an op's error carries the far end's stderr (docker's prose,
			// image and container names chosen by whoever pushed the config), and
			// this lands in the status line -- the one remote string that reached
			// the terminal without going through the parse-boundary scrub.
			m.status, m.statusErr = scrub(msg.err.Error()), true
			// Re-read anyway. A failed `compose up` is not a no-op -- it can
			// start two of three services and fail on the third -- so the rows
			// are least trustworthy exactly when the command reports failure.
			// This used to return here, leaving the page as it was before a
			// command that had already changed the box.
			return m, m.fetch()
		}
		// Keep spinning until the refreshed inventory lands. Re-reading rather
		// than guessing is deliberate -- a stop that half-worked should show as
		// half-worked -- but it means the truth arrives a moment after the
		// command does, and the row must not claim to know anything in between.
		if m.settling == nil {
			m.settling = map[string]bool{}
		}
		m.settling[msg.key] = true
		return m, m.fetch()

	case runOutputMsg:
		m.run.append(string(msg))
		return m, m.run.wait()

	case monitorMsg:
		// Dropped if another app's chart was asked for while this was in
		// flight, the same guard logsMsg needs and for the same reason.
		if msg.app != m.monitorOf {
			return m, nil
		}
		m.monitorReady = true
		if msg.err != nil {
			m.status, m.statusErr = "could not read the proxy's access log", true
			return m, nil
		}
		m.monitor, m.vols, m.sysLog = msg.rows, msg.vols, msg.hist
		m.span, m.hasSpan = msg.span, msg.hasSpan
		return m, nil

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
		if m.scroll > m.maxScroll() {
			m.scroll = m.maxScroll()
		}
		return m, nil

	case connectMsg:
		if msg.res.ok() {
			m.tgt = msg.tgt
			m.form = newAddForm(msg.tgt)
			return m, m.fetch()
		}
		// Back to the field, with the address still in it and a reason under
		// it. Everything here is recoverable by typing something else.
		m.scr = screenLogin
		if msg.res.kind == reachUnknownHost {
			return m.ask(m.trustPrompt(msg)), nil
		}
		m.status, m.statusErr = msg.res.summary(msg.tgt), true
		return m, nil

	case runDoneMsg:
		m.run.done, m.run.err, m.run.result = true, msg.err, msg.result

		// A failure stays in the footer with the last few lines of output under
		// it. They are the only diagnosis there is now that the stream is not on
		// screen, and "exit status 1" on its own is not one. See runState.tail.
		if msg.err != nil {
			m.prompt = &prompt{kind: promptResult}
			return m, m.fetch()
		}

		// One value to hand over goes straight to the clipboard, and the page
		// you started from comes back with a line saying what happened. That is
		// a rotation: the host keys did not move, so the deploy key is the only
		// thing there is to choose, and a screen offering one choice is a
		// screen asking you to press a key it already knows the answer to.
		//
		// Only when the copy WORKED. The key is held in memory and nowhere
		// else, so dismissing the screen without it on the clipboard is losing
		// it -- a failed copy keeps the screen, where the error is readable and
		// the value is still there.
		//
		// Keyed on the rotation, not on the result offering one value. An edit to
		// an app's names offers one too, and its value is the host keys -- which
		// are readable off the box for as long as it exists and are one keypress
		// away on the app's row. Copying that silently and closing the screen
		// would hide the only place the new value is spelled out.
		if msg.result != nil && msg.result.rotated {
			if err := copyToClipboard(msg.result.key); err == nil {
				m.prompt = nil
				m.status, m.statusErr = msg.result.app+" key rotated and copied — update KOMIZO_DEPLOY_KEY", false
				return m, m.fetch()
			}
		}

		// Two values a new app needs in GitHub: the screen stays until it is
		// dismissed, because there is a choice to make about which to copy.
		// Nothing to hand over is reported as one line, because "it worked"
		// needs one line.
		if msg.result != nil {
			m.prompt = &prompt{kind: promptResult}
			return m, m.fetch()
		}
		m.prompt = nil
		m.status, m.statusErr = "done", false
		// A box that has just been set up is a different box: the setup screen
		// has to give way to the index, and only a fresh read can say so.
		if m.scr == screenSetup {
			return m, m.beginLoading(m.fetch())
		}
		return m, m.fetch()
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// A question in the footer takes the keys while it is open, whatever screen
	// is behind it -- otherwise typing an app's name to confirm its removal
	// would also be pressing the keys that act on it. The init screen included:
	// setting a server up now runs in its footer rather than on a page of its
	// own, and "enter" must not start it twice.
	if m.prompt != nil {
		return m.handlePromptKey(msg)
	}

	switch m.scr {
	case screenIndex:
		return m.handleIndexKey(msg)
	case screenLogin:
		return m.handleLoginKey(msg)
	case screenLogs:
		return m.handleLogsKey(msg)
	case screenMonitor:
		return m.handleMonitorKey(msg)
	case screenSetup:
		return m.handleSetupKey(msg)
	}
	return m, nil
}

// What the cursor can land on. One flat list, in the order the page draws it.
type focusKind int

const (
	focusKomizo    focusKind = iota // the komizo the box was set up with
	focusProxy                      // the shared reverse proxy
	focusGate                       // the proxy's on-demand TLS gate
	focusApp                        // one app
	focusContainer                  // one container belonging to an app
	focusAdd                        // the row that adds one, under the list
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
	// the ones that are pure fact do not -- which is why the os and komizo cli
	// rows are absent (nothing acts on them) and the komizo server row is here (u
	// updates it). This list has to agree with the page: the cursor is an index
	// into it, so a row that moves on screen and not here selects its neighbour.
	out = append(out, focusItem{kind: focusKomizo, app: -1, ctr: -1})
	// The proxy sits below the facts, at the head of the live block it fronts.
	// Its on-demand TLS gate follows on its own row, so whether a wildcard app
	// can get certificates is a fact on the page rather than a flag you have to
	// remember to have set.
	if m.proxy.installed {
		out = append(out, focusItem{kind: focusProxy, app: -1, ctr: -1})
		out = append(out, focusItem{kind: focusGate, app: -1, ctr: -1})
	}
	for i, a := range m.apps {
		out = append(out, focusItem{kind: focusApp, app: i, ctr: -1})
		for j := range a.containers {
			out = append(out, focusItem{kind: focusContainer, app: i, ctr: j})
		}
	}
	// Last, under the apps, because that is where it is drawn and this list is
	// in page order. It is always present -- on a box with no apps it is the
	// only thing to select, which is the one screen where it matters most.
	out = append(out, focusItem{kind: focusAdd, app: -1, ctr: -1})
	return out
}

// firstAppRow is where the app rows begin, or 0 on a box with none.
func (m model) firstAppRow() int {
	if i := m.rowIndex(focusApp); i >= 0 {
		return i
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

// handleIndexKey drives the one screen there is.
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
func (m model) handleIndexKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
		// Enter is the monitor for everything that has one. It used to start
		// and stop the things that run -- the "primary action" -- which put
		// "take this off the internet" on the key pressed by reflex. Looking
		// is the reflex; the lifecycle moved to s.
		switch f := m.focused(); f.kind {
		case focusKomizo, focusProxy:
			// The whole machine, from either of the rows that ARE the whole
			// machine. The komizo server row is the box itself; the proxy row sees
			// every request to every app, and is the only thing here that can be
			// asked about all of them at once. Both questions are on one screen, so
			// both rows open it.
			return m.openMonitor("", "")
		case focusApp:
			if f.app >= 0 {
				return m.openMonitor(m.apps[f.app].name, "")
			}
		case focusContainer:
			if c := m.focusedContainer(); c != nil {
				return m.openMonitor(c.app, c.service)
			}
		case focusGate:
			// The gate has no monitor of its own -- enter edits it, the way it
			// adds on the add row. Setting, changing or clearing the ask URL is
			// the only thing this row does.
			return m.ask(m.gatePrompt()), nil
		case focusAdd:
			// Adding had a global "a" once, on the reasoning that it does not
			// act on a selection so it should not need one. True, and beside
			// the point: it is done a handful of times in a server's life, and
			// a permanent line in the footer for something that rare crowds
			// out the keys that are not. It is a row now, which is also where
			// someone looks for it.
			m.form = newAddForm(m.tgt)
			return m.ask(m.addPrompt()), nil
		}
		return m, nil

	case "s":
		// Start or stop, in the direction the thing is not currently in. One
		// key for both directions, and the hint says which way it will go --
		// separate start and stop keys means eventually pressing the wrong
		// one, and the wrong one here takes something off the internet.
		return m.startStopAction()

	case "u":
		// Updating lives on the komizo server row, which displays the version it
		// changes. One operation re-runs the whole setup -- Docker included -- so
		// there is no separate docker row to update.
		if m.focused().kind == focusKomizo {
			m = m.ask(m.updateKomizoPrompt())
		}

	case "c":
		// Changing which image the host trusts for its config. Re-running setup
		// is what applies it; this is the same operation, named after what you
		// are actually doing rather than hidden behind "add".
		if i := m.selectedApp(); i >= 0 {
			m = m.ask(m.configPrompt(m.apps[i]))
		}

	case "a":
		// The names CI dials this app by -- the third answer the add form asks
		// for, and the only one that used to be unrepeatable.
		//
		// Beside "h" rather than folded into it, because they are two halves of
		// one value and only one of them is editable: the KEYS are the box's,
		// which is what h copies, and the NAMES are this app's, which is what
		// this edits. Pressing h afterwards gives you the same string this
		// screen just handed over.
		if i := m.selectedApp(); i >= 0 {
			m = m.ask(m.knownAsPrompt(m.apps[i]))
		}

	case "h":
		// The app's own KOMIZO_KNOWN_HOSTS. On the app row for the same reason
		// rotate and remove are: it is that app's value, and offering it beside
		// a container's name would say it belonged to the container.
		//
		// "h" rather than "k", which is already up. It is one of the two keys
		// the index freed when it stopped offering vim aliases for enter and
		// esc, and the other one -- "l" -- is logs.
		if i := m.selectedApp(); i >= 0 {
			m = m.copyKnownHosts(m.apps[i])
		}

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
			return m.openLogs(proxyContainer, "proxy", "", "", containerLogCmd(proxyContainer))
		case focusContainer:
			c := m.focusedContainer()
			return m.openLogs(c.name, c.service, c.app, c.service, containerLogCmd(c.name))
		case focusApp:
			if f.app < 0 {
				return m, nil
			}
			a := m.apps[f.app]
			return m.openLogs("app:"+a.name, a.name, a.name, "", stackLogCmd(a))
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

	}
	return m, nil
}

// copyKnownHosts puts one app's KOMIZO_KNOWN_HOSTS on the clipboard.
//
// Per app, because that is the granularity it is consumed at: the value lives
// in one repo's variables, and known_hosts is matched on the exact name the
// client dialled. The KEYS are the box's and every app pins the same ones; the
// NAMES are the repo's. It used to be one server-wide value built from every
// name every app had mentioned, which put one app's hostnames in another app's
// repository for nothing.
//
// Not a secret -- it needs integrity, not secrecy -- so it is copied like any
// other text.
func (m model) copyKnownHosts(a appRow) model {
	if len(m.srv.hostKeys) == 0 {
		m.status, m.statusErr = "the server's host keys have not been read yet", true
		return m
	}
	// An app added before the names were recorded has none; the name this
	// session connected by is the best guess, and usually the right one.
	names := a.knownAs
	if len(names) == 0 {
		m.status, m.statusErr = "no names recorded for "+a.name+"; using "+m.tgt.host, true
	}
	if err := copyToClipboard(formatKnownHosts(m.tgt.namedFor(names), m.srv.hostKeys)); err != nil {
		m.status, m.statusErr = err.Error(), true
	} else if !m.statusErr {
		m.status, m.statusErr = a.name+" known_hosts copied", false
	}
	return m
}

// openLogs gives a log the whole window.
//
// Always a fresh fetch, and always from the top. Reopening the same log after
// something has happened to it is the common case, and showing yesterday's
// scroll position in yesterday's text would be worse than a moment's wait.
func (m model) openLogs(key, label, app, svc, cmd string) (tea.Model, tea.Cmd) {
	cmd2 := m.withSpin(func() {
		m.logs, m.logsOf, m.logsLabel, m.logsCmd = "", key, label, cmd
		m.logsApp, m.logsSvc = app, svc
		m.logsReady, m.scroll = false, 0
		m.status, m.statusErr = "", false
		// Where esc goes afterwards: back to the screen the log was opened
		// from, because "back" that lands somewhere other than where you were
		// is not back.
		m.logsBack = m.scr
		m.scr = screenLogs
	}, fetchLogs(m.tgt, key, cmd))
	return m, cmd2
}

// startStopAction is what s does to the three things that run -- the proxy, an
// app, a container -- in the direction the thing is not currently in.
//
// Stopping asks first; starting does not. The asymmetry is the point: starting
// something that is already meant to be running is recoverable by definition,
// and stopping takes a service off the internet.
func (m model) startStopAction() (tea.Model, tea.Cmd) {
	switch f := m.focused(); f.kind {
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
	// One ticker, however many rows are moving: withSpin asks whether anything
	// was already spinning before the row is marked, because starting a second
	// runs the animation at double speed.
	return m.withSpin(func() {
		if m.busy == nil {
			m.busy = map[string]bool{}
		}
		m.busy[key] = true
		m.status, m.statusErr = "", false
	}, runOp(m.tgt, key, cmd))
}

// spinning reports whether any row is mid-action or waiting for the refresh
// that follows one.
func (m model) spinning() bool {
	if m.scr == screenMonitor && !m.monitorReady {
		return true
	}
	return len(m.busy)+len(m.settling) > 0 || m.running() ||
		m.scr == screenLoading || (m.scr == screenLogs && m.loading())
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
	// tlsAsk carried forward, not dropped: reinstalling to pick up a newer Caddy
	// must not silently remove the on-demand TLS gate and break every wildcard
	// app on the box. Changing the gate is a separate action (t).
	o := proxyOpts{network: m.net.name, image: m.proxy.image, tlsAsk: m.proxy.tlsAsk}
	if o.network == "" {
		o.network = defaultNetwork
	}
	if o.image == "" {
		o.image = defaultProxy
	}
	q := "Reinstall the proxy from " + o.image + "?"
	doing := "Reinstalling the proxy"
	detail := "Certificates survive — they are in a volume. Every app is briefly unreachable."
	if !m.proxy.installed {
		q = "Install the proxy from " + o.image + " on '" + o.network + "'?"
		doing = "Installing the proxy"
		detail = "One Caddy terminates HTTPS for every app, so no app publishes a port."
	}
	return prompt{
		question: q,
		detail:   detail,
		action: func(m *model, _ string) tea.Cmd {
			return tea.Batch(m.startOp(doing), m.startProxy(o))
		},
	}
}

// gatePrompt sets, changes or clears the on-demand TLS gate -- the endpoint
// Caddy asks before issuing a certificate for a wildcard hostname. It is a
// per-server setting (Caddy takes one such block per machine), so it lives on
// the proxy row rather than an app's. Applying it is a proxy re-run with the new
// TLS_ASK, exactly what `komizo proxy --tls-ask` does; the network and image are
// carried forward so the gate is the only thing that changes.
func (m model) gatePrompt() prompt {
	net := m.net.name
	if net == "" {
		net = defaultNetwork
	}
	img := m.proxy.image
	if img == "" {
		img = defaultProxy
	}
	detail := "The URL Caddy asks before issuing an on-demand certificate for a " +
		"wildcard hostname (e.g. http://<app>-gate/internal/tls-ask). Leave it " +
		"empty to remove the gate."
	if m.anyWildcard() {
		detail += " Apps here use a wildcard, so without a gate their certificates fail."
	}
	return prompt{
		kind:     promptInput,
		question: "On-demand TLS ask endpoint",
		detail:   detail,
		typed:    m.proxy.tlsAsk, // prefill the current value for editing
		check:    validateTLSAsk, // empty is valid and means "remove the gate"
		action: func(m *model, v string) tea.Cmd {
			doing := "Setting the TLS gate"
			if v == "" {
				doing = "Removing the TLS gate"
			}
			return tea.Batch(m.startOp(doing),
				m.startProxy(proxyOpts{network: net, image: img, tlsAsk: v}))
		},
	}
}

// updateKomizoPrompt re-runs the whole server setup, bringing the box to the
// version of komizo now in your hand.
//
// One operation rather than three. The Docker, agent and proxy steps were once
// updated apart -- the reasoning being that a box could want a newer Docker
// without wanting komizo's scripts rewritten -- but the thing people actually
// need is the confidence that the box matches the CLI, and three separate
// updates is three chances to have run only some of them. So this is a fresh
// install over a running box: it re-runs setup, reinstalls the agent, and
// updates the proxy IF the box has one (a box that opted out stays proxy-less),
// then stamps this version. Apps keep running and nothing is deleted.
func (m model) updateKomizoPrompt() prompt {
	return prompt{
		question: "Update komizo on " + m.tgt.host + " to " + versionLabel(versionText()) + "?",
		detail: "Re-runs the whole setup — Docker, the komizo agent, and the " +
			"reverse proxy if this box has one — leaving it at " + versionLabel(versionText()) +
			". The apps keep running, recorded history is kept, and nothing is deleted.",
		action: func(m *model, _ string) tea.Cmd {
			return tea.Batch(
				m.startOp("Updating komizo on "+m.tgt.host),
				m.startKomizoUpdate())
		},
	}
}

// runLoginTUI opens the interface with no host, on the screen that asks for
// one. Everything the argument path does before starting -- resolving the port,
// probing, offering to accept an unseen host key -- happens inside the program
// instead, as a command and a question in the footer. See connect.
func RunLoginTUI() error {
	p := tea.NewProgram(newLoginModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func RunTUI(hostArg string, port int, portExplicit bool, assumeYes bool) error {
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

// toggleMouse asks the terminal for mouse events, and gives them back.
//
// OFF by default, which is the whole point. A program that asks for mouse
// events is a program the terminal stops using them on: drags go to the
// application instead of selecting text, so wheel scrolling costs you the
// ability to highlight anything on any screen. That is a bad trade to make on
// someone's behalf. Selecting and copying is something every terminal already
// does, it works the same everywhere, and it is what people reach for without
// being told.
//
// So the wheel is opt-in, for the long pages where it earns its keep -- a log,
// or a monitor with four charts on it -- and pressing s again gives selection
// back. Keyboard scrolling works throughout either way.
//
// (Most terminals let you hold shift to bypass mouse reporting. That is worth
// knowing and is neither universal nor discoverable, which is a reason to have
// this key rather than a reason not to need it.)
func (m model) toggleMouse() (tea.Model, tea.Cmd) {
	m.mouseOn = !m.mouseOn
	if m.mouseOn {
		m.status, m.statusErr = "wheel scrolling on — s to select text again", false
		return m, tea.EnableMouseCellMotion
	}
	m.status, m.statusErr = "", false
	return m, tea.DisableMouse
}

// typing reports whether a keystroke belongs to a field rather than to the
// page. Every printable key does while a form or an input prompt is open, so
// the select toggle must not eat "s" out of a hostname.
func (m model) typing() bool {
	if m.scr == screenLogin {
		return true
	}
	if m.prompt == nil {
		return false
	}
	switch m.prompt.kind {
	case promptTypeWord, promptInput, promptForm:
		return true
	}
	return false
}
