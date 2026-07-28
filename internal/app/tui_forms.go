package app

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// --- adding an app ---------------------------------------------------------

type addForm struct {
	fields  []field
	focus   int
	problem string
}

type field struct {
	label string
	help  string
	value string
	check func(string) error
}

// render shows the value, with a caret only where one can be typed.
func (f field) render(focused bool) string {
	if focused {
		return f.value + barStyle.Render("▏")
	}
	if f.value == "" {
		return dimStyle.Render("—")
	}
	return f.value
}

// renderFields is the shared layout for every form, so they cannot drift apart.
// Only the focused row shows its help, which keeps a three-field form to a
// screenful instead of a wall of grey.
func renderFields(fields []field, focus int) string {
	var b strings.Builder
	for i, fl := range fields {
		caret := "  "
		label := dimStyle.Render(pad(fl.label, 14))
		if i == focus {
			caret = barStyle.Render("▍") + " "
			label = titleStyle.Render(pad(fl.label, 14))
		}
		b.WriteString(gutter + caret + label + " " + fl.render(i == focus) + "\n")
		if i == focus {
			for _, ln := range wrap(fl.help, 62) {
				b.WriteString(gutter + "    " + dimStyle.Render(ln) + "\n")
			}
		}
	}
	return b.String()
}

// The third field is always asked, and that is the fix for a real trap.
//
// Host keys are pinned per NAME: known_hosts is matched on the exact string the
// client dialled, so entries written for one name match nothing when CI dials
// another, and the deploy stops with "no entry for <name>" while the correct
// keys sit in the variable.
//
// This used to be asked only when connected by IP, on the reasoning that a box
// reached by name is already being reached by the name CI uses. That is true of
// exactly one arrangement -- one app, one domain, and you administer it over
// that same domain. It is false the moment a box has an admin name of its own:
// connect as komizo.example.com to set up an app CI deploys to app.example.com,
// and the interface offered no way to say so at all.
//
// So it is always here, blank means "no others", and either kind of address
// works on both sides.
func newAddForm(t target) addForm {
	help := "optional. Other names CI connects by, comma-separated — host keys are pinned per name, so a name missing here fails the deploy."
	if t.isIP() {
		help = "the domain CI connects by, if it is not this address — host keys are pinned per name. Comma-separated for more than one."
	}
	return addForm{fields: []field{
		{
			label: "app name",
			help:  "letters, digits, underscore, hyphen. Names its directory, account and commands.",
			check: validateApp,
		},
		{
			label: "config image",
			help:  "registry path with NO tag, e.g. ghcr.io/you/blog-config. Where the host reads compose.yml from.",
			check: validateConfigImage,
		},
		{
			label: "known as",
			help:  help,
			check: validateKnownAs,
		},
	}}
}

// validateKnownAs checks a comma-separated list of extra hostnames. Empty is
// fine: most boxes are reached by one name.
func validateKnownAs(s string) error {
	for _, h := range splitNames(s) {
		if err := validateHost(h); err != nil {
			return err
		}
	}
	return nil
}

// mergeNames adds names not already present, preserving order. Adding a second
// app on the same box should not repeat the first one's aliases.
func mergeNames(have, add []string) []string {
	seen := map[string]bool{}
	for _, h := range have {
		seen[h] = true
	}
	for _, h := range add {
		if !seen[h] {
			seen[h] = true
			have = append(have, h)
		}
	}
	return have
}

// splitNames turns "a.example.com, b.example.com" into its parts, dropping
// blanks so a trailing comma is not an error.
func splitNames(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// knownAs is the extra hostnames, if any were given.
func (f addForm) knownAs() []string { return splitNames(f.fields[2].value) }

func (f addForm) app() string    { return strings.TrimSpace(f.fields[0].value) }
func (f addForm) config() string { return strings.TrimSpace(f.fields[1].value) }

// trustPrompt asks whether to add a host key to known_hosts, with the
// fingerprints beside the question.
//
// The same trust ssh asks for on a first connection, and asked the same way --
// except that komizo puts the fingerprints next to the question instead of
// making you run a second command to see them. They came off the network and
// nothing has verified them, which is exactly why the question exists.
func (m model) trustPrompt(msg connectMsg) prompt {
	detail := "These came from the network, not from the server's own /etc/ssh. " +
		"Compare them against your provider's console before accepting."
	for _, ln := range msg.fp {
		detail += "\n" + ln
	}
	scan, tgt := msg.scan, msg.tgt
	return prompt{
		question: "Trust the host key for " + tgt.host + "?",
		detail:   detail,
		action: func(m *model, _ string) tea.Cmd {
			if _, err := writeKnownHosts(scan); err != nil {
				m.status, m.statusErr = err.Error(), true
				return nil
			}
			return m.beginLoading(connect(tgt))
		},
	}
}

// addPrompt is the add form, asked in the footer with the list still behind it.
func (m model) addPrompt() prompt {
	return prompt{
		kind:     promptForm,
		question: "Add an app",
		detail: "A deploy keypair is generated in memory here; only the public " +
			"half is sent, and the private half is never written to disk — copy " +
			"it when it appears or rotate the key for another.",
	}
}

func (m model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := &m.form
	switch msg.String() {
	case "esc":
		m.prompt = nil
		return m, nil
	case "tab", "down":
		f.focus = (f.focus + 1) % len(f.fields)
	case "shift+tab", "up":
		f.focus = (f.focus - 1 + len(f.fields)) % len(f.fields)
	case "enter":
		if f.focus < len(f.fields)-1 {
			f.focus++
			return m, nil
		}
		for i := range f.fields {
			if err := f.fields[i].check(strings.TrimSpace(f.fields[i].value)); err != nil {
				f.problem = err.Error()
				f.focus = i
				return m, nil
			}
		}
		// The names go to the app, not onto the connection. They are recorded
		// on the box beside the app, so this app's value can be rebuilt on any
		// later run -- which is what the merge onto the target was reaching
		// for and could not do: it lasted one session and leaked one app's
		// names into the next app's value.
		//
		// Adding an app is not destructive, so it runs without a confirmation
		// step -- re-running it on an existing app is how you repair one.
		m.prompt = nil
		return m, tea.Batch(
			m.startOp(fmt.Sprintf("Setting up %q", f.app())),
			m.startAdd(f.app(), f.config(), f.knownAs()))
	case "backspace":
		v := f.fields[f.focus].value
		if v != "" {
			f.fields[f.focus].value = v[:len(v)-1]
		}
		f.problem = ""
	default:
		if s := typedText(msg); s != "" {
			f.fields[f.focus].value += s
			f.problem = ""
		}
	}
	return m, nil
}

// --- the shared reverse proxy ----------------------------------------------

// --- setting the server up -------------------------------------------------

// A fresh box gets a statement and one decision, not a form.
//
// It asked two questions once -- the network name, then whether to install the
// proxy. Both are gone. The network is the worst possible thing to decide on a
// server with nothing on it, and the proxy is what every app on the box is
// reached through, so "no" only meant finding out later. It is always
// installed; stopping it afterwards is one keypress on the server screen.

func (m model) handleSetupKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "ctrl+c":
		return m, tea.Quit

	case "left", "right", "tab":
		// Two buttons, so one key that moves is enough and either arrow does
		// it. Nothing here is a list where direction carries meaning.
		m.setupCancel = !m.setupCancel
		return m, nil

	case "enter":
		if m.setupCancel {
			// Cancel closes the program. It is the honest end on the one screen
			// whose only action is setting the server up: there is nothing else
			// to do here, and leaving someone on a page with no next step is
			// worse than closing it.
			return m, tea.Quit
		}
		// Straight to the loading screen. What is about to be installed was
		// worth reading while it was a decision; once it is running, the only
		// thing anyone wants from the page is whether it is still going -- and
		// leaving the description up behind a spinner reads as though it is
		// still asking. The box is re-read when it finishes, and that read
		// decides where you land: the monitor, or back here if it did not take.
		cmd := m.startOp("Setting up " + m.tgt.host)
		m.scr = screenLoading
		return m, tea.Batch(cmd,
			m.startInit(initOpts{network: defaultNetwork, image: defaultProxy}))
	}
	return m, nil
}

// viewSetup is what a fresh box gets: what will happen to it, and one decision.
//
// Centred to match the two other pages that are one thing on an empty screen --
// the login field and the loading pane.
//
// One paragraph, in plain words. It used to name the three things being
// installed in a table -- docker, the network, the proxy -- with a line each
// saying what they are. That is a list of implementation for someone who has
// not decided to use the tool yet: the network in particular is a detail they
// cannot act on, cannot change from here, and will never think about again. The
// two facts that matter to the person reading are that it takes a minute and
// that nothing else on the machine is touched.
func (m model) viewSetup() string {
	// The same opening as the login screen and the loader, then a gap, then
	// what this particular box needs. The gap is doing real work: it separates
	// what the tool is from what is being asked, which are two different
	// registers -- one is a banner, the other is a decision.
	lines := append(m.brandBlock(), "", "")
	if m.srv.state == "docker-stopped" {
		lines = append(lines,
			dot("warn")+" "+warnStyle.Render("Docker is installed but not running; continuing starts it"),
			"")
	}
	lines = append(lines,
		titleStyle.Render("This server is not set up yet"),
		"",
		m.setupButtons())
	return m.centred(lines...)
}

// setupButtons is the decision, at the end of what there is to read.
//
// Verbs, not answers. "yes" and "no" need a question above them to mean
// anything, and the question was a line saying "Set it up?" over a screen whose
// title already says the server is not set up -- the same sentence twice, once
// as a statement and once as a question. A button that says what it does needs
// nothing above it.
//
// Marked with the same accent bar the app list uses for its cursor, rather than
// a box or reverse video: a selection should look the same wherever it is on
// screen, and this page has one for the first time.
func (m model) setupButtons() string {
	// Both buttons are the same width, marker included, so the pair does not
	// slide sideways as the cursor moves between them -- the line is centred,
	// and a pair that changed width would shift under the key that moved it.
	button := func(label string, selected bool) string {
		if selected {
			return barStyle.Render(cursorBar) + " " + pad(selStyle.Render(label), 6)
		}
		return "  " + pad(dimStyle.Render(label), 6)
	}
	return button("start", !m.setupCancel) + "    " + button("cancel", m.setupCancel)
}

// --- the prompts, shared -----------------------------------------------------
//
// Both the list and the detail screen offer rotate and remove. They were
// written out at the call site once, which is how the detail screen came to
// advertise two keys it did not handle: the help line was copied, the handler
// was not.

func (m model) rotatePrompt(a appRow) prompt {
	q := fmt.Sprintf("Rotate the deploy key for %q?", a.name)
	return prompt{
		question: q,
		detail: "The current key stops working immediately — update KOMIZO_DEPLOY_KEY " +
			"before this app's next deploy.",
		action: func(m *model, _ string) tea.Cmd {
			return tea.Batch(
				m.startOp("Rotating the deploy key for "+a.name),
				m.startRotate(a.name))
		},
	}
}

func (m model) removePrompt(a appRow) prompt {
	// Names the host. The header used to carry it on every screen; now that it
	// does not, the most destructive prompt has to say which box it means
	// rather than "this server".
	q := fmt.Sprintf("Remove %q from %s?", a.name, m.tgt.host)
	return prompt{
		kind:     promptTypeWord,
		word:     a.name,
		question: q,
		detail: "Deletes " + a.dir + ", its volumes, the account " + a.user +
			" and its rules. Images stay in your registry. Cannot be undone.",
		action: func(m *model, _ string) tea.Cmd {
			return tea.Batch(m.startOp("Removing "+a.name), m.startRemove(a.name))
		},
	}
}

// --- changing which config image an app trusts -------------------------------
//
// The pin is the trust anchor: root decides where the host will accept config
// from, and CI cannot override it. That is exactly why it needs an obvious way
// to be changed -- a wrong value fails at deploy time as "not found" from the
// registry, which reads like a build problem rather than a setting on the box.
//
// An input in the footer rather than a form of its own. It is one value, it is
// already on the app's row two lines above, and editing it in place means you
// can see what you are changing it from.
func (m model) configPrompt(a appRow) prompt {
	return prompt{
		kind:     promptInput,
		question: "Config image for " + a.name,
		detail:   "Registry path with NO tag — the deploy supplies that.",
		typed:    a.image,
		check:    validateConfigImage,
		action: func(m *model, v string) tea.Cmd {
			// Unchanged is not a no-op worth running: re-running setup would
			// reinstall everything to arrive back where it started.
			if v == a.image {
				return nil
			}
			return tea.Batch(m.startOp("Pointing "+a.name+" at "+v), m.startConfigChange(a.name, v))
		},
	}
}
