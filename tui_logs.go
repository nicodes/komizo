package main

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// A log gets the whole window.
//
// It used to open as a pane under the app list, which meant the thing you came
// to read was whatever fitted in the space left over -- usually a dozen lines,
// on the screen where the list you were no longer looking at was taking up
// twenty. A log is either worth reading or it is not, and if it is, it is worth
// the page.
//
// The page is deliberately the same page: identical title, identical footer in
// the identical place. Only the middle changes, so nothing about where you are
// has to be re-learned. That used to be true by careful imitation -- this
// window measured its own chrome and pinned its own footer, and the app list
// did something similar but not the same. Both go through one frame now, so it
// is true by construction. See tui_frame.go.

// loading reports whether we are waiting for the log to arrive.
//
// Tracked with a flag rather than inferred from an empty body: a container that
// has genuinely logged nothing also has an empty body, and it would otherwise
// spin forever waiting for output that has already arrived.
func (m model) loading() bool { return m.logsOf != "" && !m.logsReady }

// logLines is the log as lines, without a trailing blank.
func (m model) logLines() []string {
	if m.logs == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(m.logs, "\n"), "\n")
}

// Five keys, and the footer names all five. There were eleven: g/G and
// home/end and pgup/pgdn and space and f and b, plus left and h as second ways
// to go back -- a vi mode and a pager mode layered over a window that shows one
// screenful of text.
//
// Shift with the arrow you are already using replaces both jump pairs. It is
// the same gesture for "further" that every list has, so there is nothing extra
// to learn, and it means no key on this page is undocumented.
//
// No refresh either. `docker logs --tail 40` is a snapshot, and this window is
// where you read one -- if it has moved on, esc and l give you the current one.
func (m model) handleLogsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit

	case "esc":
		m.scr = screenMonitor
		m.status, m.statusErr = "", false
		return m, nil

	case "up":
		m.scroll--
	case "down":
		m.scroll++
	case "shift+up":
		m.scroll = 0
	case "shift+down":
		m.scroll = m.maxScroll()

	case "c":
		if m.logs == "" {
			return m, nil
		}
		// The whole log, not the part on screen. Copying what happens to be
		// visible would make the result depend on the size of the window.
		if err := copyToClipboard(m.logs); err != nil {
			m.status, m.statusErr = err.Error(), true
		} else {
			m.status, m.statusErr = "copied", false
		}
		return m, nil
	}

	// Deliberately unclamped here. Update clamps it on the way out, against a
	// viewport this keypress may have just changed the height of -- "copy" adds
	// a status line, and a bound computed before it would be one line stale.
	return m, nil
}

// viewLogs is every line of the log.
//
// What fits, and where in it we are, is the frame's business. This used to
// slice the log itself, which meant the window knew its own height and the
// scroll arithmetic existed in two places that had to agree.
func (m model) viewLogs() string {
	if m.loading() {
		return m.loadingPane()
	}

	lines := m.logLines()
	if len(lines) == 0 {
		return m.centred(dimStyle.Render("this one has logged nothing"))
	}

	// A blank row before the first line, so the log does not start hard against
	// the header. It is part of the body rather than the header, which means it
	// scrolls away with the top of the log -- correct, since the gap is there to
	// separate the log's beginning from the title, and once you are past the
	// beginning there is nothing to separate.
	var b strings.Builder
	b.WriteString("\n")
	for _, ln := range lines {
		b.WriteString(gutter + dimStyle.Render(ln) + "\n")
	}
	return b.String()
}

// logsKeys is what this window answers to -- all of it, with nothing left
// undocumented. Same shape as the list's: move first, leave last.
//
// esc goes back and q quits, which is what those keys do everywhere else. They
// used to both go back, while the footer claimed q quit.
func (m model) logsKeys() string {
	return helpLine(m.width, "↑↓", "scroll", "shift+↑↓", "ends",
		"c", "copy", "esc", "back", "q", "quit")
}
