package main

import (
	"strings"
)

// viewList is the whole interface: the box, then what is running on it.
//
// The box had a page of its own once, behind "s". The two are not separable
// questions -- an app being up and anything being able to reach it have the
// same answer most of the time -- and a stopped proxy stayed invisible for as
// long as it took someone to think of looking. State you have to navigate to is
// state you learn about late.
func viewList(m model) string {
	var b strings.Builder
	b.WriteString(m.boxSection())
	b.WriteString(m.proxySection())

	if len(m.apps) == 0 {
		b.WriteString("\n" + gutter + titleStyle.Render("No apps yet") + "\n")
		b.WriteString("\n" + para(gutter, "An app is a compose stack with its own directory, deploy account\nand privileged commands."))
		b.WriteString("\n" + gutter + keyStyle.Render("a") + dimStyle.Render(" adds one.") + "\n")
		return b.String()
	}

	b.WriteString(section("Apps") + "\n")

	// Focus indices continue from the sections above, so the cursor runs
	// straight down the page.
	idx := m.boxRows()
	// No header. Four columns, and each one says what it is: a status dot, a
	// name, what it is doing, and where it comes from or goes to. A header row
	// naming them would have to name two different things per column, because
	// an app and a container are not the same shape -- and having tried that,
	// the labels were the least useful line in the block.
	var rows []treeRow
	for _, a := range m.apps {
		// Everything but the status dot is muted. The dot is the only thing on
		// the row that is ever urgent, and it can only say so if nothing beside
		// it is competing -- a table of white text with one coloured glyph in
		// it reads as one coloured glyph.
		rows = append(rows, treeRow{idx: idx, cells: []string{
			m.rowDot("app:"+a.name, appDot(a)),
			dimStyle.Render(a.name),
			dimStyle.Render(a.stateText()),
			short(a.version),
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
			rows = append(rows, treeRow{idx: k.idx, cells: k.cells})
		}
	}
	b.WriteString(tree(rows, m.cursor))

	if m.status != "" {
		mark, style := dot("ok"), okStyle
		if m.statusErr {
			mark, style = dot("err"), errStyle
		}
		b.WriteString("\n" + gutter + mark + " " + style.Render(m.status) + "\n")
	}
	return b.String()
}

// footer is the question, when one is being asked, and the key hints when not.
// The same place either way, so the answer appears where the keys were.
//
// Ruled off and pinned to the bottom of the terminal by the caller. It is the
// only part of the page that is ever interactive, and a question that moves up
// and down as the list above it grows is a question you have to look for.
func (m model) footer() string {
	body := m.helpLines()
	if m.prompt != nil {
		body = m.prompt.view()
	}
	return "\n" + gutter + dimStyle.Render(strings.Repeat("─", ruleWidth(m.width))) + "\n" +
		trimTrailing(body)
}

// boxRows is how many focusable rows the two sections above the apps
// contribute, so the app rows can continue the numbering.
func (m model) boxRows() int {
	n := 1 // the docker row is always there and always actionable
	if len(m.srv.hostKeys) > 0 {
		n++
	}
	if m.proxy.installed {
		n++
	}
	return n
}

// boxSection is the server itself, address included -- it was the header's job
// until the header became just the name of the tool.
//
// The docker row is where re-running server setup lives -- that is what an
// update IS, and it is the version on that row that changes. Putting the action
// on the row showing the thing it acts on means one less thing to look up, the
// same reason the proxy's actions sit on its own row.
//
// The network is left as a plain fact: it is created by setup rather than
// chosen here, and moving it strands every app that names it.
func (m model) boxSection() string {
	var b strings.Builder
	b.WriteString(section("Server"))
	b.WriteString(kv("address", dimStyle.Render(m.tgt.display())))
	b.WriteString(kvSel("docker", dimStyle.Render(orDash(m.srv.docker)), m.cursor == 0))
	kg, kt := m.knownHostsLine()
	b.WriteString(kvDot("known_hosts", kg, kt, len(m.srv.hostKeys) > 0 && m.cursor == 1))
	return b.String()
}

// proxySection sits between the server and the apps because that is what it is:
// the thing every app on the box reaches the outside through, and the first
// suspect when one of them is up and still not answering.
//
// It had a settings page once, with a field for the network and one for the
// image. Two questions to reach a button that almost always wanted the values
// already on screen -- so the values are simply shown, in the same label/value
// rows the Server section uses, and changing either is a flag on the command
// line where it belongs for something you do once.
func (m model) proxySection() string {
	var b strings.Builder
	b.WriteString(section("Proxy"))
	pg, pt := m.proxyLine()
	ng, nt := m.networkLine()
	if !m.proxy.installed {
		b.WriteString(kvDot("status", pg, pt, false))
		b.WriteString(kvDot("network", ng, nt, false))
		return b.String()
	}
	// After the docker row, and after known_hosts when there is one.
	i := 1
	if len(m.srv.hostKeys) > 0 {
		i = 2
	}
	b.WriteString(kvDot("status", pg, pt, m.cursor == i))
	b.WriteString(kvDot("network", ng, nt, false))
	// Last of the three: the image is the one that never changes on its own.
	// Status and network are things to check; this is a thing to confirm.
	b.WriteString(kv("image", dimStyle.Render(orDash(m.proxy.image))))
	return b.String()
}

// startStop names the direction enter will go, so one key for both is not a
// coin toss.
func startStop(running bool) string {
	if running {
		return "stop"
	}
	return "start"
}

// enterLabel is what enter will do to the selected row, for anything that wants
// it outside the help line.
func (m model) enterLabel() string {
	k := m.contextKeys()
	for i := 0; i+1 < len(k); i += 2 {
		if k[i] == "enter" {
			return k[i+1]
		}
	}
	return ""
}

// The help is two lines, and the split is the point: what is always true, then
// what is true of the thing under the cursor.
//
// One line meant every key on the page was on screen at once -- thirteen pairs
// of them -- so the two that always work were no easier to find than the four
// that only work on an app. Splitting them makes the bottom line answer "what
// can I do with THIS", which is the question someone actually has.
func (m model) helpLines() string {
	return help("↑↓", "select", "a", "add an app", "R", "refresh", "q", "quit") +
		trimTrailing(help(m.contextKeys()...))
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
	case focusServer:
		return []string{"enter", "update server"}

	case focusHosts:
		return []string{"enter", "copy SSH_KNOWN_HOSTS"}

	case focusProxy:
		return []string{"enter", startStop(m.proxy.running()),
			"l", "proxy log", "p", "reinstall"}

	case focusApp:
		if f.app < 0 {
			return nil
		}
		a := m.apps[f.app]
		return append([]string{"enter", startStop(a.up()), "l", a.name + " log"},
			appActions()...)

	case focusContainer:
		// No app actions here. They are app-wide, and offering them beside one
		// container's name reads as though they apply to that container.
		c := m.focusedContainer()
		return []string{"enter", startStop(c.up()), "l", c.service + " log"}
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
func appActions() []string {
	return []string{"c", "config image", "r", "rotate key", "x", "remove"}
}

// short trims a commit SHA to something readable without losing which it is.
func short(v string) string {
	if v == "" || v == "none" {
		return dimStyle.Render("never deployed")
	}
	if len(v) > 12 {
		v = v[:12]
	}
	return dimStyle.Render(v)
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
