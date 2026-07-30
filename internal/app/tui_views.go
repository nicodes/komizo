package app

import (
	"strings"
)

// viewIndex is the whole interface: the box, then what is running on it.
//
// The box had a page of its own once, behind "s". The two are not separable
// questions -- an app being up and anything being able to reach it have the
// same answer most of the time -- and a stopped proxy stayed invisible for as
// long as it took someone to think of looking. State you have to navigate to is
// state you learn about late.
func viewIndex(m model) string {
	var b strings.Builder
	b.WriteString(m.boxSection())

	// No blank line under the heading. Every app below is a group with a blank
	// line above it, so one here made the first group sit lower than the rest
	// and read as though something were missing from it.
	// No heading here either: the tree is unmistakably the apps, and nothing
	// else on the page has that shape. The blank line above it still separates
	// them from the box's own rows.
	b.WriteString("\n")

	if len(m.apps) == 0 {
		b.WriteString("\n")
		b.WriteString(para(gutter, "An app is a compose stack with its own directory, deploy account\nand privileged commands.") + "\n")
		b.WriteString(m.addRow())
		return b.String()
	}

	// Focus indices continue from the sections above, so the cursor runs
	// straight down the page.
	idx := m.rowIndex(focusApp)
	// No header. Four columns, and each one says what it is: a status dot, a
	// name, what it is doing, and where it comes from or goes to. A header row
	// naming them would have to name two different things per column, because
	// an app and a container are not the same shape -- and having tried that,
	// the labels were the least useful line in the block.
	var rows []treeRow
	for i, a := range m.apps {
		// A blank line between apps, so each one and its containers read as a
		// block rather than as one long column. Between them and not after, so
		// the last group is separated from the add row by exactly the same gap
		// as the groups are from each other.
		//
		// A row with no cells: tree gives it the same treatment as any other,
		// which is a line with nothing on it. It carries idx -1, so it is not
		// somewhere the cursor can land.
		if i > 0 {
			rows = append(rows, treeRow{idx: -1})
		}

		// Everything but the status dot is muted. The dot is the only thing on
		// the row that is ever urgent, and it can only say so if nothing beside
		// it is competing -- a table of white text with one coloured glyph in
		// it reads as one coloured glyph.
		// Column order matters more than it looks. Widths are shared across
		// every row in the table, and the LAST column is the only one that can
		// afford to overflow -- the frame clips rather than wraps. Routes is
		// far and away the widest thing here (ormos publishes seven hostnames),
		// so it goes last and everything bounded goes before it.
		//
		// The sparkline learnt this the hard way: put after the routes column,
		// it started past the right edge of a 132-column terminal and was
		// clipped away entirely, on a box that was serving traffic.
		// spark names the strip's cell so the selection highlight can leave
		// its colours alone; see tree.
		rows = append(rows, treeRow{idx: idx, spark: 4, cells: []string{
			m.rowDot("app:"+a.name, appDot(a)),
			dimStyle.Render(a.name),
			dimStyle.Render(a.stateText()),
			// The deployed commit, in a column of its own rather than in
			// brackets after the name. Bracketed, it pushed the name's width
			// around: a long SHA on one app and none on the next left the
			// column ragged, and the thing the eye is scanning down is the
			// name.
			short(a.version),
			// The last half hour of requests, failures stacked red on top of
			// the blue. Dots rather than a flat line when nothing has arrived:
			// a line along zero claims a measurement, and "nobody has asked
			// this box for anything" is a different statement from "zero
			// requests".
			m.sparkFor(a.name),
			dimStyle.Render(a.image),
		}})
		// Each container under its app, with the hostnames that reach IT.
		//
		// Routes used to sit on the app row, which answered "what does this box
		// serve" but not "what serves this hostname" -- and the second is the
		// question you have when one domain is down and the rest are fine.
		// Putting them on the container turns two lookups into a glance.
		idx++
		byContainer := a.routesByContainer(m.net)

		// Children are built first so the last one can be corner-joined, and
		// the join lives INSIDE the name cell -- indenting the name without
		// pushing every column after it three places right.
		type child struct {
			idx   int
			cells []string
		}
		var kids []child
		for _, c := range a.containers {
			kids = append(kids, child{idx: idx, cells: []string{
				m.rowDot(c.name, stateDot(c.state)),
				dimStyle.Render(c.service),
				// Docker's wording goes in the app's uptime column rather than
				// beside it. It is the same measurement in another format, so a
				// placeholder to keep them apart would only be an empty column
				// down the middle of the block.
				dimStyle.Render(c.stateText()),
				// The app's version column, holding what this container is
				// listening on. Both answer "which one is this", and neither is
				// wide, so they share a column rather than each having one that
				// is empty on the other kind of row.
				dimStyle.Render(c.portsList()),
				// What this container is listening on, read out of its own
				// network namespace. Not the image, which after naming a
				// service after it says the same word twice.
				//
				// This used to come from the app's caddy fragment -- where the
				// proxy DIALLED, which is a declaration and could be wrong.
				// Apps ship no fragment now, and the port is observed instead:
				// strictly better information from a source that cannot drift.
				// The same strip the app row carries, for the requests this
				// container served. Attribution comes from the app's own
				// hostnames file, so a container nobody named there gets a
				// BLANK rather than dots -- see sparkForService.
				m.sparkForService(c.app, c.service),
				m.routesCell(c, byContainer[c.name]),
			}})
			idx++
		}
		for i, k := range kids {
			join := "├ "
			if i == len(kids)-1 {
				join = "└ "
			}
			k.cells[1] = dimStyle.Render(join) + k.cells[1]
			rows = append(rows, treeRow{idx: k.idx, spark: 4, cells: k.cells})
		}
	}
	b.WriteString(tree(rows, m.cursor))
	b.WriteString("\n" + m.addRow())
	// No status line here. It used to be appended after the last app, which put
	// the reply to a keypress in a different place on every host and, once the
	// list was longer than the terminal, off the bottom of it. It is in the
	// footer now, where every page's is. See statusLine.
	return b.String()
}

// addRow is the last row of the Apps section: the one that adds one.
//
// A row rather than a key, because a key is a promise that it is worth keeping
// in your head, and this is done a handful of times in the life of a server.
// The footer only has room for the things you do constantly.
//
// Drawn like the tree's rows and not like a button -- a leading "+" where a
// status dot would be, since it is the one row in the section with no state to
// report. It selects and acts exactly like everything above it.
func (m model) addRow() string {
	selected := m.focused().kind == focusAdd
	glyph, label := dimStyle.Render("+"), dimStyle.Render("add an app")
	if selected {
		return barStyle.Render(cursorBar) + " " + glyph + "  " + brighten(label) + "\n"
	}
	return gutter + glyph + "  " + label + "\n"
}

// rowIndex is where the first row of a kind sits in the focus list, or -1.
//
// READ from focusItems rather than recounted. Two places used to recount it --
// the proxy row and the top of the app list -- and a recount is a second
// definition of the same thing. When the known_hosts row left the focus list,
// both kept counting it, so every row below was numbered one too high: the
// cursor highlighted one row while the keys acted on another, and on a box with
// a single app and no containers the app row and "+ add an app" lit up
// together, because the app had been handed the add row's index.
func (m model) rowIndex(kind focusKind) int {
	for i, f := range m.focusItems() {
		if f.kind == kind {
			return i
		}
	}
	return -1
}

// boxSection is the server itself. Not its address: that is in the header, as
// the first crumb, because it is the one fact on this page that every other
// fact is relative to.
//
// Updating the box lives on the komizo server row -- that is what an update IS,
// and it is the version on that row that changes. Putting the action on the row
// showing the thing it acts on means one less thing to look up, the same reason
// the proxy's actions sit on its own row.
//
// The network is left as a plain fact: it is created by setup rather than
// chosen here, and moving it strands every app that names it.
func (m model) boxSection() string {
	var b strings.Builder
	// No heading. Two groups of a few rows each did not need naming: the page is
	// short enough that the shape of it -- flat rows, then a tree -- says which
	// is which, and a heading over three lines was a line spent on a label.
	//
	// The blank line stays. It came from the heading, and dropping it too ran
	// the block into the header above it: the labels went, the structure they
	// marked did not.
	b.WriteString("\n")
	// What the box IS and what this tool put on it -- os, the two komizo versions,
	// and the proxy with its TLS gate -- in one block; then, set off by a blank
	// line, the three bars of what the machine is spending. The proxy sits with
	// the facts rather than over the bars now: it is a thing you act on, like the
	// komizo rows above it, and the bars below are pure measurement.
	//
	// server over cli: the komizo the box was provisioned with -- the row this
	// interface can be wrong about, and the one u updates -- then the cli you are
	// running, so the box's version reads first and yours sits under it for the
	// only comparison that matters: do they match.
	//
	// No docker row. Its version was a fact nobody acted on -- the update that
	// re-runs Docker is on the komizo server row -- and a box that has got this
	// far has a working Docker by definition.
	b.WriteString(kv("os", dimStyle.Render(m.srv.osName())))
	b.WriteString(kvSel("komizo server", m.komizoServerLine(), m.cursor == m.rowIndex(focusKomizo)))
	b.WriteString(kv("komizo cli", m.komizoCliLine()))
	b.WriteString(m.proxyRows())
	b.WriteString(m.gateRows())
	// The usage bars are their own block, one blank line down -- but only when
	// there are readings to draw. A blank line over nothing would open a gap the
	// box section does not otherwise have.
	if usage := m.serverUsage(); usage != "" {
		b.WriteString("\n")
		b.WriteString(usage)
	}
	// No known_hosts row. The value is per app -- the keys are the box's, the
	// names are the repo's -- so it is copied from the app it belongs to.
	return b.String()
}

// proxyRows is the shared reverse proxy, one row, network included.
//
// The network used to be a row of its own. It is not a thing anyone acts on --
// it is created by setup and every app names it -- and a full row gave a
// permanent line to a fact whose only interesting state is "missing", which
// the proxy row can carry in the one sentence that state needs.
//
// It had a settings page once, with a field for the network and one for the
// image. Two questions to reach a button that almost always wanted the values
// already on screen -- so the values are simply shown, and changing either is
// a flag on the command line where it belongs for something you do once.
//
// No image either. It is the one fact here that cannot change without someone
// deciding it should: status and network are things to check, and an image
// pinned by a flag on a command run once is a thing to confirm -- which is
// not what this page is for. `komizo list` still prints it, and reinstalling
// names it in the question.
func (m model) proxyRows() string {
	// "proxy", not "status". Under its own heading the row could be called that
	// and be unambiguous; here it would read as the server's status, which is a
	// different thing and one this page does not claim to know.
	pg, pt := m.proxyLine()
	return kvDot("proxy", pg, pt,
		m.proxy.installed && m.cursor == m.rowIndex(focusProxy))
}

// gateRows is the proxy's on-demand TLS gate, one row directly under the proxy
// it belongs to. Only when a proxy exists: a gate with nothing to gate for is
// not a thing to show.
func (m model) gateRows() string {
	if !m.proxy.installed {
		return ""
	}
	gg, gt := m.gateLine()
	return kvDot("tls gate", gg, gt, m.cursor == m.rowIndex(focusGate))
}

// startStop names the direction enter will go, so one key for both is not a
// coin toss.
func startStop(running bool) string {
	if running {
		return "stop"
	}
	return "start"
}

// keyLabel is what a key will do to the selected row, for anything that wants
// it outside the help line.
func (m model) keyLabel(key string) string {
	k := m.contextKeys()
	for i := 0; i+1 < len(k); i += 2 {
		if k[i] == key {
			return k[i+1]
		}
	}
	return ""
}

// The help is one line, in a fixed order: move, act, everything else, leave.
//
// It was two -- what always works, then what the selected row can do -- on the
// reasoning that the split told you which was which. It did, and it cost more
// than it paid: two lines of grey to read instead of one, a footer that changed
// height as you moved, and the two ends of the line you actually use ("select"
// and "quit") separated by everything in between.
//
// The order does the same work the split did, without the second line. Moving
// is always first and leaving is always last, so the two keys that work on
// every screen are in the same place on every screen, and what changes as the
// cursor moves is the middle -- which is exactly what "what can I do with this"
// means. Enter leads that middle, because it is the one you press.
func (m model) helpLines() string {
	pairs := []string{"↑↓", "select"}
	var rest []string
	k := m.contextKeys()
	for i := 0; i+1 < len(k); i += 2 {
		// Enter jumps the queue rather than keeping its place among the row's
		// other keys: it is the one that does the obvious thing, and its label
		// is the row's own answer to "and what happens if I just press enter".
		if k[i] == "enter" {
			pairs = append(pairs, k[i], k[i+1])
			continue
		}
		rest = append(rest, k[i], k[i+1])
	}
	pairs = append(pairs, rest...)
	// Not the select-mode toggle. On this screen s belongs to the row -- it
	// starts and stops the thing selected -- and the toggle is advertised on
	// the log and monitor screens, which have room and are where text is
	// worth copying.
	return helpLine(m.width, append(pairs, "q", "quit")...)
}

// contextKeys is what the selected row can do. Every entry here acts on that
// row and nothing else, which is why none of them are on the line above.
func (m model) contextKeys() []string {
	keys := m.rowKeys()
	// A proxy that does not exist has no row to select, so the key that
	// installs one is offered wherever the cursor is until it does. Adding an
	// app has the same shape and is handled differently -- it lives on the top
	// line, because it is done often enough to be worth a permanent slot.
	if !m.proxy.installed {
		keys = append(keys, "p", "install a proxy")
	}
	return keys
}

func (m model) rowKeys() []string {
	switch f := m.focused(); f.kind {
	case focusKomizo:
		return []string{"enter", "monitor", "u", "update"}

	case focusProxy:
		return []string{"enter", "monitor", "s", startStop(m.proxy.running()),
			"l", "logs", "p", "reinstall"}

	case focusGate:
		set := "set gate"
		if m.proxy.tlsAsk != "" {
			set = "change gate"
		}
		return []string{"enter", set}

	case focusApp:
		if f.app < 0 {
			return nil
		}
		a := m.apps[f.app]
		return append([]string{"enter", "monitor", "s", startStop(a.up()), "l", "logs"},
			appActions()...)

	case focusContainer:
		// No app actions here. They are app-wide, and offering them beside one
		// container's name reads as though they apply to that container.
		c := m.focusedContainer()
		return []string{"enter", "monitor", "s", startStop(c.up()), "l", "logs"}

	case focusAdd:
		return []string{"enter", "add an app"}
	}
	return nil
}

// appActions are the keys that act on the selected app, and are offered only
// when the cursor is on the app's own row.
//
// Adding is deliberately not among them: it creates an app rather than acting
// on one, and it lives on the always-available line. Removing very much is --
// "remove" offered anywhere else is an invitation to a question nobody wants to
// have to ask, which is "remove what?".
// Labels are short because the row is what says which thing they act on. They
// used to name it -- "config image", "rotate key", and "l ormos log" naming the
// selected app -- which repeated the cursor back at you and cost the width that
// keeps the whole line on an eighty-column window.
// komizoLine is what komizo has installed on this box, and whether it matches
// what this komizo would install.
//
// Compared by stamp rather than announced as a version. "Up to date" is not a
// property of a release number, it is the answer to "would running the update
// change anything" -- and a hash of what gets written is the only thing that
// answers that without somebody remembering to bump a constant.
// komizoCliLine is the komizo you are running, on its own row -- the binary in
// your hand, bright, so "which komizo is this" is a glance. It is a fact about
// your machine rather than the server, so it carries no action and nothing to be
// out of date against; the server row directly below is where the two compare.
func (m model) komizoCliLine() string {
	return keyStyle.Render(versionLabel(versionText()))
}

// komizoServerLine is the komizo that provisioned the box, and whether it
// matches the cli row over it. Read against that row: the same version on both
// is a box that is up to date; every other state here is a reason to press u.
func (m model) komizoServerLine() string {
	switch {
	case !m.srv.komizoInstalled:
		// Never set up.
		return warnStyle.Render("not installed") + dimStyle.Render("  · u to install")
	case m.srv.komizoVersion == "":
		// Installed, but by a komizo old enough to have recorded no version --
		// only a stamp. Nothing to show and nothing to compare, so read it as
		// needing an update: an update is what starts recording the version, and
		// showing the raw stamp as if it were one only reads as noise.
		return warnStyle.Render("version not recorded") + dimStyle.Render("  · u to update")
	case m.komizoOutOfDate():
		return dimStyle.Render(m.boxVersion()) + dimStyle.Render("  ") +
			warnStyle.Render("out of date") + dimStyle.Render("  · u to update")
	}
	return dimStyle.Render(m.boxVersion())
}

// komizoOutOfDate is whether running the update would change anything on this
// box. Either signal is enough: a different content stamp (the sampler changed,
// which the version alone would miss while it is "dev"), or a different release
// version (something else komizo installs changed between releases, which the
// stamp alone would miss when that something is not the sampler).
//
// A box that recorded no version at all is handled before this in komizoLine --
// it has nothing to compare and is always treated as needing an update.
func (m model) komizoOutOfDate() bool {
	if m.srv.komizo != komizoStamp() {
		return true
	}
	return m.srv.komizoVersion != "" && m.srv.komizoVersion != versionText()
}

// boxVersion is how the box's setup version reads on its row. Only called once a
// version is recorded; the version-less box has its own branch in komizoLine.
func (m model) boxVersion() string {
	return versionLabel(m.srv.komizoVersion)
}

// versionLabel prefixes a "v" onto a release number, and leaves the honest
// non-versions ("dev", a VCS pseudo-version) as they are.
func versionLabel(v string) string {
	if v == "" || v == "dev" {
		return v
	}
	if v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

func appActions() []string {
	return []string{"h", "hosts", "c", "config", "r", "rotate", "x", "remove"}
}

// short trims a commit SHA to something readable without losing which it is.
func short(v string) string {
	return dimStyle.Render(shortText(v))
}

// shortText is the same trimming without the styling, for the places that build
// a longer string around it.
func shortText(v string) string {
	if v == "" || v == "none" {
		return "never deployed"
	}
	if len(v) > 12 {
		v = v[:12]
	}
	return v
}

// rowDot is a row's status, or a spinner when that row has an action running.
//
// The spinner replaces the dot in place rather than appearing beside it: they
// are the same one column, so nothing shifts, and the row you just pressed
// enter on is the row that visibly reacts. That is the whole feedback for an
// action that no longer takes over the screen.
func (m model) rowDot(key, state string) string {
	if m.busy[key] || m.settling[key] {
		return spinner(m.spin)
	}
	return state
}

// stateDot is running or not, in one glyph, in the first column.
//
// One shape for every row that runs -- the proxy, an app, a container -- so
// "what is up" is a single vertical scan rather than three different notations.
// It replaced a count on the app row, which was a number you had to compare
// against a service list you did not have.
//
// Docker's own prose still sits alongside it, dimmed: "Exited (1) 2 minutes
// ago" carries the exit code and the age, and both are the first thing you want
// once the dot has told you something is wrong.
//
// Restarting keeps its own colour. A container in a crash loop reports
// "Restarting", which reads as activity and is usually the opposite.
func stateDot(state string) string {
	switch state {
	case "running":
		return dot("ok")
	case "restarting":
		return dot("warn")
	default:
		return dot("err")
	}
}

// appDot summarises an app from its containers.
//
// Amber for a partial stack is the case worth separating: every container down
// is usually deliberate, and half of them down never is.
func appDot(a appRow) string {
	if len(a.containers) == 0 {
		return stateDot(map[bool]string{true: "running", false: ""}[a.up()])
	}
	up := 0
	for _, c := range a.containers {
		if c.up() {
			up++
		}
	}
	switch up {
	case 0:
		return dot("err")
	case len(a.containers):
		return dot("ok")
	default:
		return dot("warn")
	}
}

// routesCell is the hostnames reaching a container, plus the one problem that
// is invisible everywhere else.
//
// An alias clash -- two containers answering to the same name on the shared
// network -- cannot be seen from any row on its own, because each of them looks
// perfectly healthy. Caddy round-robins between them, so it fails
// intermittently rather than outright. It used to be reported in a block under
// the list; with that block gone it belongs on the rows it is about.
func (m model) routesCell(c containerRow, routes []string) string {
	if dupes := m.net.duplicateAliases(); len(dupes) > 0 {
		for _, mem := range m.net.members {
			if mem.container != c.name {
				continue
			}
			for _, a := range mem.aliases {
				if _, clash := dupes[a]; clash {
					return errStyle.Render("alias clash: "+a) +
						dimStyle.Render("  shared with another container")
				}
			}
		}
	}
	return routesOrNone(routes)
}

// routesOrNone keeps the column readable when nothing is published through the
// proxy, which is normal for a worker, a cron job or a database.
func routesOrNone(routes []string) string {
	if len(routes) == 0 {
		return dimStyle.Render("—")
	}
	return dimStyle.Render(strings.Join(routes, ", "))
}

// selectKey names what pressing s would GET you, not what it turns off.
//
// The mouse belongs to the terminal by default, so most of the time this offers
// the wheel. Once the wheel is on it offers selection back, because that is the
// thing you have lost and the thing you are looking for a way to get.
func (m model) selectKey() []string {
	if m.mouseOn {
		return []string{"s", "select"}
	}
	return []string{"s", "wheel"}
}
