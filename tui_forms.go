package main

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
	// choices, when set, makes this a pick-one field: left/right and space
	// cycle it and typing does nothing. A yes/no answer should not be a text
	// box you can misspell.
	choices []string
}

// cycle advances a choice field, wrapping. No-op on a text field.
func (f *field) cycle(by int) {
	if len(f.choices) == 0 {
		return
	}
	at := 0
	for i, c := range f.choices {
		if c == f.value {
			at = i
		}
	}
	f.value = f.choices[(at+by+len(f.choices))%len(f.choices)]
}

// render shows the value, with a caret only where one can be typed.
func (f field) render(focused bool) string {
	if len(f.choices) > 0 {
		var parts []string
		for _, c := range f.choices {
			if c == f.value {
				parts = append(parts, keyStyle.Render("["+c+"]"))
			} else {
				parts = append(parts, dimStyle.Render(" "+c+" "))
			}
		}
		return strings.Join(parts, " ")
	}
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

func newAddForm() addForm {
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
	}}
}

func (f addForm) app() string    { return strings.TrimSpace(f.fields[0].value) }
func (f addForm) config() string { return strings.TrimSpace(f.fields[1].value) }

func (m model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := &m.form
	switch msg.String() {
	case "esc":
		m.scr = screenList
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
		// Adding an app is not destructive, so it runs without a confirmation
		// step -- re-running it on an existing app is how you repair one.
		m.scr = screenRunning
		m.run = newRunState(fmt.Sprintf("Setting up %q", f.app()))
		return m, m.startAdd(f.app(), f.config())
	case "backspace":
		v := f.fields[f.focus].value
		if v != "" {
			f.fields[f.focus].value = v[:len(v)-1]
		}
		f.problem = ""
	default:
		if s := msg.String(); len(s) == 1 {
			f.fields[f.focus].value += s
			f.problem = ""
		}
	}
	return m, nil
}

func (f addForm) view() string {
	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render("Add an app") + "\n\n")
	b.WriteString(renderFields(f.fields, f.focus))
	if f.problem != "" {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(f.problem) + "\n")
	}
	b.WriteString("\n" + para(gutter, "A deploy keypair is generated on this machine; only the public half\nis sent. Safe to run again on an app that already exists."))
	b.WriteString(help("tab", "next field", "enter", "confirm", "esc", "cancel"))
	return b.String()
}

// --- confirming something destructive --------------------------------------

type confirmPrompt struct {
	title string
	body  []string
	// confirmWord, when set, must be typed out in full. Reserved for actions
	// that delete data -- a single keypress is too easy to hit by accident.
	confirmWord string
	typed       string
	action      func(*model) tea.Cmd
}

func (m model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := &m.confirm
	switch msg.String() {
	case "esc":
		m.scr = screenList
		return m, nil
	case "enter":
		if c.confirmWord != "" && c.typed != c.confirmWord {
			return m, nil
		}
		m.scr = screenRunning
		m.run = newRunState(c.title)
		return m, c.action(&m)
	case "backspace":
		if c.typed != "" {
			c.typed = c.typed[:len(c.typed)-1]
		}
	default:
		if c.confirmWord != "" {
			if s := msg.String(); len(s) == 1 {
				c.typed += s
			}
		}
	}
	return m, nil
}

func (c confirmPrompt) view() string {
	var b strings.Builder
	mark := dot("warn")
	style := warnStyle
	if c.confirmWord != "" {
		mark, style = dot("err"), errStyle
	}
	b.WriteString("\n" + gutter + mark + " " + style.Render(c.title) + "\n\n")
	for _, l := range c.body {
		b.WriteString(gutter + "  " + dimStyle.Render(l) + "\n")
	}
	if c.confirmWord != "" {
		typed := c.typed
		if typed == c.confirmWord {
			typed = okStyle.Render(typed)
		}
		b.WriteString(fmt.Sprintf("\n"+gutter+"type %s to confirm  %s%s\n",
			keyStyle.Render(c.confirmWord), typed, barStyle.Render("▏")))
		if c.typed == c.confirmWord {
			b.WriteString(help("enter", "do it", "esc", "cancel"))
		} else {
			b.WriteString(help("esc", "cancel"))
		}
	} else {
		b.WriteString(help("enter", "confirm", "esc", "cancel"))
	}
	return b.String()
}

// --- the shared reverse proxy ----------------------------------------------

// proxyFormModel is deliberately separate from addForm: the proxy is per-server
// rather than per-app, so it shares no fields with adding an app, and folding
// them together would mean a form where half the inputs are always ignored.
type proxyFormModel struct {
	fields  []field
	focus   int
	problem string
}

func newProxyForm() proxyFormModel {
	return proxyFormModel{fields: []field{
		{
			label: "network",
			value: defaultNetwork,
			help:  "CHANGING THIS BREAKS EVERY APP until each one's compose.yml names the new network too.",
			check: validateNetworkName,
		},
		{
			label: "caddy image",
			value: defaultProxy,
			help:  "pin a digest or minor version here if you do not want :2 moving under you.",
			check: func(s string) error {
				if s == "" || !onlyChars(s, imageChars) {
					return fmt.Errorf("that is not a valid image reference: %q", s)
				}
				return nil
			},
		},
	}}
}

// set pre-fills from what is already on the server, so re-running to change one
// value does not reset the rest.
func (f *proxyFormModel) set(p proxyRow) {
	if p.network != "" && p.network != "?" {
		f.fields[0].value = p.network
	}
	if p.image != "" && p.image != "?" {
		f.fields[1].value = p.image
	}
}

func (f proxyFormModel) opts() proxyOpts {
	return proxyOpts{
		network: strings.TrimSpace(f.fields[0].value),
		image:   strings.TrimSpace(f.fields[1].value),
	}
}

func (m model) handleProxyFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := &m.proxyForm
	switch msg.String() {
	case "esc":
		m.scr = screenList
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
		m.scr = screenRunning
		title := "Installing the shared reverse proxy"
		if m.proxy.installed {
			title = "Updating the shared reverse proxy"
		}
		m.run = newRunState(title)
		return m, m.startProxy(f.opts())
	case "backspace":
		v := f.fields[f.focus].value
		if v != "" {
			f.fields[f.focus].value = v[:len(v)-1]
		}
		f.problem = ""
	default:
		if s := msg.String(); len(s) == 1 {
			f.fields[f.focus].value += s
			f.problem = ""
		}
	}
	return m, nil
}

func (f proxyFormModel) view(p proxyRow) string {
	var b strings.Builder
	if p.installed {
		b.WriteString("\n" + gutter + titleStyle.Render("Proxy settings") + "\n")
		b.WriteString(dimStyle.Render(gutter+"Currently "+p.state+" on network "+p.network) + "\n\n")
	} else {
		b.WriteString("\n" + gutter + titleStyle.Render("Install the reverse proxy") + "\n")
		b.WriteString(para(gutter, "One Caddy for the whole box. It takes ports 80 and 443, so no\napp has to publish one, and it holds no per-app config.") + "\n")
	}
	b.WriteString(renderFields(f.fields, f.focus))
	if f.problem != "" {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(f.problem) + "\n")
	}
	if f.fields[0].value != p.network && p.network != "" && p.network != "?" {
		b.WriteString("\n" + gutter + dot("warn") + " " + warnStyle.Render(
			fmt.Sprintf("moving off %q strands every app still on it", p.network)) + "\n")
		b.WriteString(para(gutter+"  ", "Each app's compose.yml names the network, so all of them need\nediting and redeploying — until then the proxy cannot reach them."))
	}
	b.WriteString("\n" + para(gutter, "Certificates need no setup — Caddy obtains and renews them for\nwhatever hostnames your apps publish. Safe to re-run."))
	b.WriteString(help("tab", "next field", "enter", "confirm", "esc", "cancel"))
	return b.String()
}

// --- setting the server up -------------------------------------------------

// initForm is what a fresh box gets instead of an empty app list. Docker used
// to arrive as a side effect of adding the first app, which meant a server had
// no state you could name and `proxy` failed on an untouched machine.
type initForm struct {
	fields  []field
	focus   int
	problem string
}

// One question, deliberately. The network name used to be asked here too, but
// it is the worst possible moment to ask: on a fresh box you cannot know
// whether the default collides, and changing it later means editing every app's
// compose.yml, since each names the network in its own config image. It is
// settable from the proxy screen and the --network flag for the rare case.
func newInitForm() initForm {
	return initForm{fields: []field{
		{
			label:   "reverse proxy",
			value:   "yes",
			choices: []string{"yes", "no"},
			help:    "one Caddy for the whole box, so no app publishes a port. Say no only if an app needs :80 itself.",
			check:   func(string) error { return nil },
		},
	}}
}

func (f initForm) opts() initOpts {
	return initOpts{
		proxy:   f.fields[0].value == "yes",
		network: defaultNetwork,
		image:   defaultProxy,
	}
}

func (m model) handleInitKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := &m.initForm
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab", "down":
		f.focus = (f.focus + 1) % len(f.fields)
	case "shift+tab", "up":
		f.focus = (f.focus - 1 + len(f.fields)) % len(f.fields)
	case "left":
		f.fields[f.focus].cycle(-1)
	case "right", " ":
		f.fields[f.focus].cycle(1)
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
		m.scr = screenRunning
		m.run = newRunState("Setting up " + m.tgt.host)
		return m, m.startInit(f.opts())
	case "backspace":
		if len(f.fields[f.focus].choices) == 0 {
			v := f.fields[f.focus].value
			if v != "" {
				f.fields[f.focus].value = v[:len(v)-1]
			}
		}
		f.problem = ""
	default:
		if s := msg.String(); len(s) == 1 && len(f.fields[f.focus].choices) == 0 {
			f.fields[f.focus].value += s
			f.problem = ""
		}
	}
	return m, nil
}

func (f initForm) view(srv serverRow) string {
	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render("Connected") +
		dimStyle.Render(" — this server is not set up yet") + "\n\n")
	if srv.state == "docker-stopped" {
		b.WriteString(gutter + dot("warn") + " " + warnStyle.Render(
			"Docker is installed but not running. Continuing will try to start it.") + "\n\n")
	} else {
		b.WriteString(para(gutter, "Nothing is installed on it yet. This adds Docker, enables it at boot,\nand creates the '"+defaultNetwork+"' network apps share. No accounts, nothing\nunder /srv — that comes later, when you add an app.") + "\n")
	}
	b.WriteString(renderFields(f.fields, f.focus))
	if f.problem != "" {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(f.problem) + "\n")
	}
	b.WriteString("\n" + para(gutter, "Safe to re-run later; this is also how you update Docker."))
	b.WriteString(help("←→", "choose", "tab", "next field", "enter", "set up", "q", "quit"))
	return b.String()
}
