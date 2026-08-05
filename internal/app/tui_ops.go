package app

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

// Operations that touch the server run as tea.Cmds and stream their output
// back as messages, so an apk install does not freeze the interface.

type appsMsg struct {
	apps    []appRow
	srv     serverRow
	proxy   proxyRow
	net     netRow
	metrics []metricRow
	// sys is one reading of the box's resources, not a rate. Rates are derived
	// against the previous reading, which only the model has.
	sys sysSample
	err error
}

type runOutputMsg string

type runDoneMsg struct {
	err    error
	result *addResult // set when the operation produced values to paste
}

// addResult is what `add` and `rotate` leave the user with: the two things
// GitHub needs.
type addResult struct {
	app string
	// host is the address CI should dial: what KOMIZO_SERVER_URL is set to. Carried
	// on the result because the screen handing over the other two values is
	// where someone is already copying from.
	host string
	// key is the private half, held in memory for as long as this screen is
	// open and written nowhere. See keys.go.
	key string
	// keyPath is set only when --key asked for a copy on disk, which the
	// interface never does.
	keyPath    string
	knownHosts string
	// port is the SSH port CI has to dial. Carried so the screen can say so:
	// KOMIZO_SERVER_URL is the bare hostname (see target.serverURL), and on a box
	// that is not on 22 the port has to reach the workflow some other way -- the
	// deploy action's own `port:` input. It used to be folded into the URL as
	// "[host]:2222", which is a known_hosts pattern that the connect action
	// refuses outright.
	port int
	// config is what the box ended up pinned to -- given on a setup, read back
	// off the server on a rotation.
	config  string
	rotated bool

	// Both values have to reach GitHub, so both are selectable and both are
	// copyable.
	//
	// onClipboard is which one is there NOW, not which have ever been copied.
	// There is one clipboard: ticking every value that had been copied at some
	// point claimed two things were on it at once, and read as the mark being
	// stuck to the first row.
	cursor      int
	onClipboard int // index, or -1 for nothing
	copyErr     string

	// Set when this was a config-image change rather than a fresh setup: the
	// GitHub values are unchanged, so telling someone to paste them again
	// would be wrong.
	changedConfig string

	// Set when this was an edit to the names CI dials the app by.
	//
	// Unlike a config-image change, this one DOES move a value in GitHub:
	// known_hosts entries are written per name, so the app's KOMIZO_KNOWN_HOSTS
	// is a different string afterwards and the repo has to be given it.
	//
	// A flag beside the list rather than "the list is not nil", because clearing
	// the names is one of the edits and an emptied list is indistinguishable
	// from an absent one -- splitNames returns nil for both. Reading the
	// difference off a slice header would have made the emptied case render as a
	// fresh app setup, telling someone to paste a deploy key that was never
	// generated.
	namesChanged bool
	changedNames []string
}

// The two things this screen exists to hand over, in the order you paste them.
const (
	resultKey = iota
	resultHosts
	resultItems
)

// rows is which values this result offers, in display order.
//
// Not always both. A rotation replaces the deploy keypair and nothing else, so
// offering the host keys beside it would say something else needs updating in
// GitHub when nothing does. An edit to the names is the mirror image: the keys
// are the box's and did not move, but they are now written against different
// names, so the host keys are the only thing there is to hand over -- and the
// deploy key is not even in memory to offer.
func (a addResult) rows() []int {
	switch {
	case a.changedConfig != "":
		return nil
	case a.namesChanged:
		return []int{resultHosts}
	case a.rotated:
		return []int{resultKey}
	}
	return []int{resultKey, resultHosts}
}

// items is how many rows this result offers.
func (a addResult) items() int { return len(a.rows()) }

// selected reports whether the cursor is on a given value. The cursor indexes
// rows(), which is not the same as the value's own id the moment a result
// offers only the second of the two.
func (a addResult) selected(id int) bool { return rowAt(a.rows(), a.cursor) == id }

// onClipboardIs reports whether a given value is the one on the clipboard NOW.
// Same indexing question as selected, and the same answer.
func (a addResult) onClipboardIs(id int) bool { return rowAt(a.rows(), a.onClipboard) == id }

// rowAt is rows[i] for an index that may be out of range or the -1 that means
// "nothing". Returns a value no row id can be.
func rowAt(rows []int, i int) int {
	if i < 0 || i >= len(rows) {
		return -1
	}
	return rows[i]
}

func (a addResult) copySelected() error {
	if a.selected(resultKey) {
		return copyToClipboard(a.key)
	}
	return copyToClipboard(a.knownHosts)
}

// sparkRange is the window the row sparklines cover.
//
// Relative to NOW, always. The sparkline on a row is "the last half hour" and
// has to stay that whatever range the monitor screen is showing -- they are
// different questions on different pages, and the poll serves every row at
// once.
//
// A function rather than two lines inside the fetch so that rule is assertable
// without a server on the other end of a connection.
func sparkRange(now time.Time) (from, to int64) {
	to = now.Unix()
	return to - sparkWindow*60, to
}

func fetchApps(t target) tea.Cmd {
	return func() tea.Msg {
		// One command, one connection. The request counts ride along on the
		// inventory rather than getting a poll of their own: every poll opens a
		// fresh SSH connection, and that -- not the probing -- is the expensive
		// part. A second ticker would double the connection rate against the
		// box to draw a line that moves one column.
		from, to := sparkRange(time.Now())
		p, err := fetchBox[box.Poll](t, "poll",
			"--from", strconv.FormatInt(from, 10),
			"--to", strconv.FormatInt(to, 10))
		if err != nil {
			if _, missing := err.(errNoAgent); missing {
				return appsMsg{err: err}
			}
			return appsMsg{err: fmt.Errorf("could not read the server's inventory: %w", err)}
		}
		inv := inventoryFromReport(p.Report)
		// Stamped on arrival rather than on the box. The interval that matters
		// is the one between two readings landing HERE, and the two clocks need
		// not agree for that to be measured correctly.
		return appsMsg{apps: inv.apps, srv: inv.srv, proxy: inv.proxy, net: inv.net,
			metrics: metricsFromBox(p.Metrics), sys: sysSampleFrom(p.Report.System, time.Now())}
	}
}

// runState buffers an operation's output so the view can show it scrolling.
type runState struct {
	title  string
	lines  []string
	ch     chan tea.Msg
	done   bool
	err    error
	result *addResult
}

func newRunState(title string) runState {
	return runState{title: title, ch: make(chan tea.Msg, 256)}
}

func (r *runState) append(s string) {
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		r.lines = append(r.lines, l)
	}
}

// wait blocks on the next chunk of output. Returning it as a Cmd keeps the
// event loop in charge of when we read.
func (r runState) wait() tea.Cmd {
	return func() tea.Msg { return <-r.ch }
}

// runTail is the last few lines of output, for a failure.
//
// The stream is collected and never shown -- a bootstrap prints hundreds of
// lines of apk and docker progress, and the operation taking the screen to
// display them was the reason it took the screen. When one fails, though, the
// error alone is often "exit status 1", and the lines before it are the whole
// diagnosis.
func (r runState) tail(n int) []string {
	if len(r.lines) <= n {
		return r.lines
	}
	return r.lines[len(r.lines)-n:]
}

func (a addResult) view() string {
	var b strings.Builder
	if a.changedConfig != "" {
		b.WriteString(gutter + dot("ok") + " " + titleStyle.Render(a.app+" now reads its config from") + "\n")
		b.WriteString(gutter + "  " + a.changedConfig + "\n")
		b.WriteString(para("\n"+gutter, "Nothing in GitHub changed -- the deploy key and host keys are the\n"+
			"same. The next deploy pulls config from here."))
		return b.String()
	}
	if a.namesChanged {
		names := strings.Join(a.changedNames, ", ")
		if names == "" {
			names = "nothing but the address you connected on"
		}
		b.WriteString(gutter + dot("ok") + " " + titleStyle.Render(a.app+" is now dialled by") + "\n")
		b.WriteString(gutter + "  " + names + "\n")
		// The one value that moved, and it has to be pasted for this to take
		// effect anywhere. A name that CI dials with no entry written against it
		// stops the deploy with "no entry for <name>" while the correct keys sit
		// in the variable -- which is the whole reason this list is editable.
		b.WriteString(a.row(resultHosts, "KOMIZO_KNOWN_HOSTS", dimStyle.Render("variable, not a secret")))
		for _, l := range strings.Split(a.knownHosts, "\n") {
			b.WriteString(gutter + "      " + dimStyle.Render(l) + "\n")
		}
		if a.copyErr != "" {
			b.WriteString("\n" + gutter + dot("warn") + " " + warnStyle.Render(a.copyErr) + "\n")
		}
		b.WriteString(para("\n"+gutter, "The deploy key is unchanged. Update this variable in the app's "+
			"repository before its next deploy."))
		return b.String()
	}
	b.WriteString(gutter + dot("ok") + " " + titleStyle.Render("Add these to the repo for "+a.app) + "\n")
	b.WriteString(dimStyle.Render(gutter+"  Settings → Secrets and variables → Actions") + "\n")

	// --- 1. the deploy key ---------------------------------------------------
	// Never rendered. This screen ends up in screenshots and scrollback, and
	// the key is not on disk to be read back later either -- it exists in this
	// process, until this screen is dismissed. Say so, because a value with no
	// value under it otherwise reads as a page that failed to load.
	b.WriteString(a.row(resultKey, "KOMIZO_DEPLOY_KEY", dimStyle.Render("secret")))
	b.WriteString(gutter + "      " + dimStyle.Render("held in memory and not shown — press c to copy it") + "\n")
	b.WriteString(gutter + "      " + dimStyle.Render("it is not saved anywhere; rotate the key to get another") + "\n")
	if a.onClipboardIs(resultKey) {
		// The key is a private credential sitting on the system clipboard, where a
		// clipboard manager may persist it. Say so, so it gets pasted and then
		// cleared rather than left there.
		b.WriteString(gutter + "      " + warnStyle.Render("on your clipboard now — paste it into GitHub, then clear your clipboard") + "\n")
	}

	// --- 2. the host keys ----------------------------------------------------
	// Rotating replaces the deploy KEYPAIR. The server's host keys are its own
	// and are untouched, so offering them here would say that something else
	// needs updating in GitHub when nothing does. They stay one keypress away
	// on the server screen.
	if a.rotated {
		b.WriteString(para("\n"+gutter, "KOMIZO_KNOWN_HOSTS and KOMIZO_SERVER_URL are unchanged — the server did\n"+
			"not move, and its own keys did not either."))
	} else {
		// Shown in full, unlike the key: a host key needs integrity, not
		// secrecy, and masking it makes a mismatch unreadable in a CI log.
		b.WriteString(a.row(resultHosts, "KOMIZO_KNOWN_HOSTS", dimStyle.Render("variable, not a secret")))
		for _, l := range strings.Split(a.knownHosts, "\n") {
			b.WriteString(gutter + "      " + dimStyle.Render(l) + "\n")
		}

		// The last two are not produced here, only repeated: the address you
		// connected on, and the name you gave the app. Variables rather than
		// lines in the workflow, so moving an app to another box -- or reaching
		// this one by another name while its DNS moves -- is a settings change.
		//
		// The app name is the weaker of the two. It is also written into the
		// app's own compose.yml, its gate service name and its images, all of
		// which are committed and all of which must agree with it; this is
		// where CI reads it, not where it is decided.
		b.WriteString("\n" + gutter + "  " + keyStyle.Render("KOMIZO_SERVER_URL") + "  " +
			dimStyle.Render("variable") + "\n")
		b.WriteString(gutter + "      " + dimStyle.Render(a.host) + "\n")
		// The hostname alone, so the port has to be said somewhere. It goes in
		// the workflow rather than in this variable: the deploy action takes it
		// as its own input, and a port inside the URL is a value ssh cannot use.
		if a.port != 0 && a.port != 22 {
			b.WriteString(gutter + "      " + dimStyle.Render(fmt.Sprintf(
				"this box listens on %d — add `port: \"%d\"` to the deploy step", a.port, a.port)) + "\n")
		}

		b.WriteString("\n" + gutter + "  " + keyStyle.Render("KOMIZO_APP_NAME") + "  " +
			dimStyle.Render("variable") + "\n")
		b.WriteString(gutter + "      " + dimStyle.Render(a.app) + "\n")
	}

	if a.copyErr != "" {
		b.WriteString("\n" + gutter + dot("warn") + " " + warnStyle.Render(a.copyErr) + "\n")
		// No fallback command to offer: there is no file to cat. Rotating is
		// how you get another one, and it is one keypress from the app's row.
		b.WriteString(para(gutter+"  ",
			"Install a clipboard tool and rotate the key again to get a fresh one."))
	}

	if a.rotated {
		b.WriteString("\n" + gutter + dot("warn") + " " + warnStyle.Render(
			"the previous key stopped working just now") + "\n")
		b.WriteString(para(gutter+"  ", "Update the secret before this app's next deploy."))
	} else {
		b.WriteString("\n" + para(gutter, "Then add app: "+a.app+" to the deploy step in that repo's workflow."))
	}
	return b.String()
}

// row renders one selectable value, marked the same way the app list marks its
// selection, with a tick once it has been copied.
func (a addResult) row(i int, name, kind string) string {
	caret, label := "  ", keyStyle.Render(name)
	if a.selected(i) {
		caret = barStyle.Render("▍") + " "
		label = keyStyle.Render(name)
	}
	mark := ""
	if a.onClipboardIs(i) {
		mark = "  " + okStyle.Render("← on the clipboard")
	}
	return "\n" + gutter + caret + label + "  " + kind + mark + "\n"
}

// stream runs a command, feeding each line back as a message.
func stream(ch chan tea.Msg, c *exec.Cmd, stdin string) error {
	c.Stdin = strings.NewReader(stdin)
	pipe, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	c.Stderr = c.Stdout
	if err := c.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		ch <- runOutputMsg(scrub(sc.Text()))
	}
	// A scan that stopped early -- a line longer than the buffer, most likely a
	// container logging one enormous JSON blob -- leaves the pipe undrained.
	// The child then blocks writing to a full pipe, Wait never returns, and
	// because every key is disabled while an operation is in flight the whole
	// interface hangs with no way out but killing the terminal.
	//
	// So say what happened and keep reading. The output is already truncated at
	// that point; the alternative is to lose the operation as well.
	if err := sc.Err(); err != nil {
		ch <- runOutputMsg(fmt.Sprintf("[output truncated: %v]", err))
		_, _ = io.Copy(io.Discard, pipe)
	}
	return c.Wait()
}

// These need the run channel, which lives in the model, so they are methods
// rather than free functions returning a Cmd.
// The target already carries any extra names -- the form records them on it
// before starting, so every later screen sees the same set.
func (m model) startAdd(app, config string, knownAs []string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		res, err := doAdd(t, app, config, knownAs, false, ch)
		ch <- runDoneMsg{err: err, result: res}
	}()
	return m.run.wait()
}

func (m model) startRotate(app string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		res, err := doAdd(t, app, "", nil, true, ch)
		ch <- runDoneMsg{err: err, result: res}
	}()
	return m.run.wait()
}

// startInit prepares the server, then optionally the proxy. Two scripts rather
// than one, streamed to the same screen: the proxy is a choice, and a box whose
// Docker install worked but whose proxy did not is still a usable server.
func (m model) startInit(o initOpts) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		c := exec.Command("ssh", t.sshArgs(envPrefix(map[string]string{"SHARED_NETWORK": o.network})+"sh -s")...)
		if err := stream(ch, c, scripts.AlpineInitScript); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("could not set the server up -- see the output above")}
			return
		}
		if err := streamAgent(ch, t); err != nil {
			ch <- runDoneMsg{err: err}
			return
		}

		// Filing it under whoever is signed in, so it appears in the app on its
		// own. NOT fatal: the box is set up and works, and what failed is the
		// half that needs the service -- failing the whole setup would make an
		// outage look like a broken server.
		ch <- runOutputMsg("")
		ch <- runOutputMsg("filing this server under your account...")
		if err := registerAndEnrol(t, "", "", nil, false, ch); err != nil {
			ch <- runOutputMsg("could not register this server: " + err.Error())
			ch <- runOutputMsg("the box is set up. Press u once the service is reachable.")
		}
		// The interface has nowhere to type a device key, so a box set up here
		// takes orders from nothing. Said rather than left to be discovered: the
		// whole urgency of komizo-be app-only.md §9 step 1 is that planting one
		// later means going back to every box, and this is the path most boxes
		// take.
		ch <- runOutputMsg("")
		ch <- runOutputMsg("to command this box from the app, run:")
		ch <- runOutputMsg("    komizo enrol --host " + t.host + " --device-key kmz_dev_...")

		ch <- runOutputMsg("")
		ch <- runOutputMsg("installing the shared reverse proxy...")
		pc := exec.Command("ssh", t.sshArgs(envPrefix(proxyEnv(proxyOpts{
			network: o.network, image: o.image,
		}))+"sh -s")...)
		if err := stream(ch, pc, scripts.AlpineProxyScript); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("the server is ready, but the proxy failed -- press p to retry it")}
			return
		}
		ch <- runDoneMsg{}
	}()
	return m.run.wait()
}

// startProxy installs or updates the one shared reverse proxy. Not destructive
// and not app-scoped, so it needs no confirmation step -- re-running it is how
// you update Caddy or move it to another network.
func (m model) startProxy(o proxyOpts) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		c := exec.Command("ssh", t.sshArgs(envPrefix(proxyEnv(o))+"sh -s")...)
		err := stream(ch, c, scripts.AlpineProxyScript)
		ch <- runDoneMsg{err: err}
	}()
	return m.run.wait()
}

// startConfigChange re-points an app at a different config image. Re-running
// the setup script is what applies it -- the same operation as adding -- but
// with the deploy key left exactly as it is: this is a setting change, and
// issuing a new key for it would break that repo's next deploy for a reason
// nobody would connect to what they just did.
//
// It used to get that for free, because a key was only generated when the file
// under ~/.ssh was missing. Keys are not kept now, so the intent has to be
// stated rather than fall out of a file check.
func (m model) startConfigChange(app, config string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		res, err := doAddKeepingKey(t, app, config, ch)
		if res != nil {
			res.changedConfig = config
		}
		ch <- runDoneMsg{err: err, result: res}
	}()
	return m.run.wait()
}

// startKnownAsChange records a different set of names for an app.
//
// The same operation as a config-image change -- re-running the setup with the
// deploy key left alone -- because there is no smaller one: the names are in the
// app's record on the box, and that record is written by the setup script.
//
// What comes back matters more here than it does for a config image, though.
// known_hosts is matched on the exact name the client dialled, so changing this
// list changes the value that app's repository has to pin, and the result screen
// hands the new one over.
func (m model) startKnownAsChange(app string, names []string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		res, err := runAddPlan(addPlan{
			tgt:  t,
			app:  app,
			user: deriveUser(app),
			// Empty, so performAdd reads the app's own off the box. The names are
			// the only thing being changed, and a value carried down from a row on
			// screen is a value that can be stale.
			config:       "",
			knownAs:      names,
			clearKnownAs: len(names) == 0,
			keepKey:      true,
		}, ch)
		if res != nil {
			res.namesChanged, res.changedNames = true, names
		}
		ch <- runDoneMsg{err: err, result: res}
	}()
	return m.run.wait()
}

func (m model) startRemove(app string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		env := map[string]string{"APP_NAME": app}
		c := exec.Command("ssh", t.sshArgs(envPrefix(env)+"sh -s")...)
		err := stream(ch, c, scripts.AlpineRemoveScript)
		ch <- runDoneMsg{err: err}
	}()
	return m.run.wait()
}

// chanProgress reports a shared operation's progress into the run pane.
type chanProgress struct{ ch chan tea.Msg }

func (p chanProgress) step(format string, a ...any) {
	// A blank line before each heading, so the pane reads the way the CLI's
	// "==>" markers do without borrowing punctuation the pane does not use.
	p.ch <- runOutputMsg("")
	p.ch <- runOutputMsg(fmt.Sprintf(format, a...))
}

func (p chanProgress) note(format string, a ...any) {
	p.ch <- runOutputMsg("  " + fmt.Sprintf(format, a...))
}

// doAdd performs the same sequence as `komizo add`, reporting progress through
// ch instead of stdout. The sequence itself lives in performAdd -- this only
// says where the output goes and how the script is piped over.
func doAdd(t target, app, config string, knownAs []string, rotate bool, ch chan tea.Msg) (*addResult, error) {
	return runAddPlan(addPlan{
		tgt:     t,
		app:     app,
		user:    deriveUser(app),
		config:  config,
		knownAs: knownAs,
		rotate:  rotate,
	}, ch)
}

// doAddKeepingKey is the same sequence with the account's existing key left in
// place -- what a config-image change wants.
func doAddKeepingKey(t target, app, config string, ch chan tea.Msg) (*addResult, error) {
	return runAddPlan(addPlan{
		tgt:     t,
		app:     app,
		user:    deriveUser(app),
		config:  config,
		keepKey: true,
	}, ch)
}

func runAddPlan(p addPlan, ch chan tea.Msg) (*addResult, error) {
	t := p.tgt
	return performAdd(p, chanProgress{ch}, func(script string, env map[string]string) error {
		c := exec.Command("ssh", t.sshArgs(envPrefix(env)+"sh -s")...)
		return stream(ch, c, script)
	})
}

// streamAgent installs komizo-box.
//
// Its own step, after the server itself is ready. This one IS fatal to what the interface can do afterwards: komizo
// reads a box through the agent now, so a box without one shows nothing at all
// rather than a working server missing a chart. It is reported as the failure
// it is, and the Docker install before it still stands.
func streamAgent(ch chan tea.Msg, t target) error {
	ch <- runOutputMsg("")
	ch <- runOutputMsg("installing the komizo agent...")
	if err := installAgent(t, ch); err != nil {
		return fmt.Errorf("the server is ready, but the agent failed to install: %w", err)
	}
	return nil
}
