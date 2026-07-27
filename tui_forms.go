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
		// Recorded on the target, not just passed to the operation, so the
		// server screen keeps showing the complete SSH_KNOWN_HOSTS afterwards.
		// It used to be handed to the add alone, which meant the one screen
		// meant to be the durable home for that value silently gave a shorter
		// answer than the add had just printed.
		m.tgt.aliases = mergeNames(m.tgt.aliases, f.knownAs())
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

// A fresh box gets a statement and one decision, not a form.
//
// It asked two questions once -- the network name, then whether to install the
// proxy. Both are gone. The network is the worst possible thing to decide on a
// server with nothing on it, and the proxy is what every app on the box is
// reached through, so "no" only meant finding out later. It is always
// installed; stopping it afterwards is one keypress on the server screen.

func (m model) handleInitKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "ctrl+c":
		return m, tea.Quit
	case "enter":
		m.scr = screenRunning
		m.run = newRunState("Setting up " + m.tgt.host)
		return m, m.startInit(initOpts{network: defaultNetwork, image: defaultProxy})
	}
	return m, nil
}

func viewInit(srv serverRow) string {
	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render("Connected") +
		dimStyle.Render(" — this server is not set up yet") + "\n\n")

	if srv.state == "docker-stopped" {
		b.WriteString(gutter + dot("warn") + " " + warnStyle.Render(
			"Docker is installed but not running. Continuing will try to start it.") + "\n\n")
	}

	b.WriteString(para(gutter, "Setting it up installs:"))
	b.WriteString("\n")
	for _, l := range [][2]string{
		{"docker", "the container runtime, enabled at boot"},
		{defaultNetwork, "the network apps share to reach each other"},
		{"caddy", "one reverse proxy, terminating HTTPS for every app"},
	} {
		b.WriteString(gutter + "  " + dimStyle.Render(pad(l[0], 10)) + " " + dimStyle.Render(l[1]) + "\n")
	}
	b.WriteString("\n" + para(gutter, "No accounts, and nothing under /srv — that comes later, when you\nadd an app. Safe to re-run; it is also how you update Docker."))
	b.WriteString(help("enter", "set it up", "q", "quit"))
	return b.String()
}

// --- the prompts, shared -----------------------------------------------------
//
// Both the list and the detail screen offer rotate and remove. They were
// written out at the call site once, which is how the detail screen came to
// advertise two keys it did not handle: the help line was copied, the handler
// was not.

func (m model) rotatePrompt(a appRow) confirmPrompt {
	return confirmPrompt{
		title: fmt.Sprintf("Rotate the deploy key for %q?", a.name),
		body: []string{
			"A new keypair is generated on this machine and installed on the server.",
			"",
			"The current key stops working immediately. Update SSH_DEPLOY_KEY in",
			"the repo's secrets before its next deploy, or that deploy will fail.",
		},
		action: func(m *model) tea.Cmd { return m.startRotate(a.name) },
	}
}

func (m model) removePrompt(a appRow) confirmPrompt {
	return confirmPrompt{
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
}

// --- changing which config image an app trusts -------------------------------
//
// The pin is the trust anchor: root decides where the host will accept config
// from, and CI cannot override it. That is exactly why it needs an obvious way
// to be changed -- a wrong value fails at deploy time as "not found" from the
// registry, which reads like a build problem rather than a setting on the box.

type configForm struct {
	app     string
	current string
	field   field
	problem string
}

func newConfigForm(a appRow) configForm {
	return configForm{
		app:     a.name,
		current: a.image,
		field: field{
			label: "config image",
			value: a.image,
			help:  "registry path with NO tag. The deploy supplies the tag.",
			check: validateConfigImage,
		},
	}
}

func (m model) handleConfigFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := &m.configForm
	switch msg.String() {
	case "esc":
		m.scr = screenDetail
		return m, nil
	case "enter":
		v := strings.TrimSpace(f.field.value)
		if err := f.field.check(v); err != nil {
			f.problem = err.Error()
			return m, nil
		}
		if v == f.current {
			m.scr = screenDetail
			return m, nil
		}
		m.scr = screenRunning
		m.run = newRunState(fmt.Sprintf("Pointing %q at %s", f.app, v))
		return m, m.startConfigChange(f.app, v)
	case "backspace":
		if f.field.value != "" {
			f.field.value = f.field.value[:len(f.field.value)-1]
		}
		f.problem = ""
	default:
		if s := msg.String(); len(s) == 1 {
			f.field.value += s
			f.problem = ""
		}
	}
	return m, nil
}

func (f configForm) view() string {
	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render("Config image for "+f.app) + "\n\n")
	b.WriteString(para(gutter, "Where the host pulls this app's compose.yml and routes from. Root\n"+
		"pins it, so CI cannot point the host somewhere else -- which is why\n"+
		"a wrong value here fails at deploy time and not before."))
	b.WriteString("\n")
	b.WriteString(renderFields([]field{f.field}, 0))
	if f.problem != "" {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(f.problem) + "\n")
	}
	if strings.TrimSpace(f.field.value) != f.current {
		b.WriteString("\n" + gutter + dimStyle.Render("was  "+f.current) + "\n")
	}
	b.WriteString(para("\n"+gutter, "The deploy key is untouched; nothing in GitHub needs changing."))
	b.WriteString(help("enter", "apply", "esc", "cancel"))
	return b.String()
}
