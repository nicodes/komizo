package app

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/nicodes/komizo-be/cli/scripts"
)

// Operations that touch the server run as tea.Cmds and stream their output
// back as messages, so an apk install does not freeze the interface.

type appsMsg struct {
	apps  []appRow
	srv   serverRow
	proxy proxyRow
	net   netRow
	err   error
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
}

// The two things this screen exists to hand over, in the order you paste them.
const (
	resultKey = iota
	resultHosts
	resultItems
)

// value returns what the cursor is pointing at. The key is a path, because its
// contents must not be held anywhere that might later be rendered.
// items is how many rows this result offers. A rotation offers one: the host
// keys did not change, so presenting them as something to copy would imply
// otherwise.
func (a addResult) items() int {
	if a.rotated {
		return 1
	}
	return resultItems
}

func (a addResult) copySelected() error {
	if a.cursor == resultKey {
		return copyToClipboard(a.key)
	}
	return copyToClipboard(a.knownHosts)
}

func fetchApps(t target) tea.Cmd {
	return func() tea.Msg {
		out, err := t.runCapture(inventoryScript)
		if err != nil {
			return appsMsg{err: fmt.Errorf("could not read the server's inventory: %w", err)}
		}
		apps, srv, proxy, net, _ := parseInventory(out)
		return appsMsg{apps: apps, srv: srv, proxy: proxy, net: net}
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
		// app's own compose.yml, its gateway service name and its images, all of
		// which are committed and all of which must agree with it; this is
		// where CI reads it, not where it is decided.
		b.WriteString("\n" + gutter + "  " + keyStyle.Render("KOMIZO_SERVER_URL") + "  " +
			dimStyle.Render("variable") + "\n")
		b.WriteString(gutter + "      " + dimStyle.Render(a.host) + "\n")

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
	if a.cursor == i {
		caret = barStyle.Render("▍") + " "
		label = keyStyle.Render(name)
	}
	mark := ""
	if a.onClipboard == i {
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
		ch <- runOutputMsg(sc.Text())
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
		ch <- runOutputMsg("")
		ch <- runOutputMsg("installing the shared reverse proxy...")
		pc := exec.Command("ssh", t.sshArgs(envPrefix(proxyEnv(proxyOpts{
			network: o.network, image: o.image,
		}))+"sh -s")...)
		if err := stream(ch, pc, scripts.AlpineProxyScript); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("the server is ready, but the proxy failed -- press s to retry it")}
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
