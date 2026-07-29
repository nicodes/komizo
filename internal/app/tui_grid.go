package app

import "strings"

// The monitor's layout: charts in rows, as many across as the terminal can give
// each of them enough width to be read.
//
// One column was the old shape, and it wasted most of a wide terminal while
// making you scroll past processor to reach memory. Charts of the same thing at
// the same moment are meant to be read against each other, which is impossible
// when only one is on screen at a time.

// panel is one chart in the grid: what it is, what it is measured in, and how
// to draw it once its width is known.
//
// The width is not known when the panel is built. It depends on how many fit
// beside it, which depends on the terminal -- so a panel carries a function
// rather than a string, and nothing is rendered until the layout is decided.
type panel struct {
	title string
	sub   string // units, in grey beside the title
	// scored records whether this chart carries the how-unusual overlay.
	//
	// Not drawn anywhere. It is here because the decision is made in three
	// different places -- traffic always, resources when there is enough
	// history, storage never -- and a rule spread across three call sites with
	// nothing naming it is a rule that drifts. It is also the only handle a test
	// has on it: the overlay is a coloured line, and colour does not survive
	// into a terminal that is not one.
	scored bool
	draw   func(w, h int) string
}

const (
	// Narrower than this and a chart stops being one: four columns go to the y
	// labels, and what is left has to hold enough braille to show a shape.
	//
	// 45, not the 30 it was when four charts shared a row. Every row is now a
	// pair -- a series and its how-unusual chart -- each carrying the page's
	// whole time range, and forty-five columns is about where a four-hour
	// window keeps a shape. Below twice that plus the gap, the pair ZIPS into
	// one column: the chart, then its how-unusual chart under it, then the
	// next chart -- the reading order the rows already had.
	minPanelWidth = 45
	panelGap      = 2
)

// grid lays panels out in rows of at most perRow, dropping to fewer columns
// when the terminal cannot afford them.
//
// Reflowed rather than scrolled sideways or clipped. The frame truncates long
// rows, so a layout that assumed width would lose its right-hand panel entirely
// on a narrow terminal -- silently, which is the failure mode this whole screen
// is built to avoid.
func (m model) grid(panels []panel, perRow, h int) string {
	if len(panels) == 0 {
		return ""
	}
	avail := m.width - len(gutter)
	if avail < minPanelWidth {
		avail = minPanelWidth
	}
	per := perRow
	if per > len(panels) {
		per = len(panels)
	}
	for per > 1 && (avail-panelGap*(per-1))/per < minPanelWidth {
		per--
	}
	cell := (avail - panelGap*(per-1)) / per

	var b strings.Builder
	for i := 0; i < len(panels); i += per {
		end := i + per
		if end > len(panels) {
			end = len(panels)
		}
		cols := make([][]string, 0, end-i)
		for _, p := range panels[i:end] {
			cols = append(cols, p.render(cell, h))
		}
		b.WriteString(joinColumns(cols, cell))
		b.WriteString("\n")
	}
	return b.String()
}

// render is one panel as a block of lines, each exactly cell wide.
//
// Title and units on ONE line -- what it is in white, what it is measured in
// beside it in grey. Two lines cost a row of every panel on the page to carry
// half a phrase, and at three or four columns that is three or four rows of
// chart given up for text that reads as one sentence anyway.
func (p panel) render(cell, h int) []string {
	out := []string{headingLine(p.title, p.sub, cell)}
	for _, ln := range strings.Split(strings.TrimRight(p.draw(cell, h), "\n"), "\n") {
		out = append(out, ln)
	}
	return out
}

// headingLine is the title, then the units, cut to fit.
//
// The SUB is cut first, and to nothing if it comes to that. A panel that cannot
// say what it is measured in is still readable; one that cannot say what it is
// is not, so the title keeps the width when there is not enough for both.
func headingLine(title, sub string, cell int) string {
	t := cut(title, cell)
	if sub == "" {
		return titleStyle.Render(t)
	}
	room := cell - lipglossWidth(t) - 2
	if room < 4 {
		return titleStyle.Render(t)
	}
	return titleStyle.Render(t) + "  " + dimStyle.Render(cut(sub, room))
}

// joinColumns puts blocks side by side, padding short ones so the next column
// starts in the same place on every row.
func joinColumns(cols [][]string, cell int) string {
	rows := 0
	for _, c := range cols {
		if len(c) > rows {
			rows = len(c)
		}
	}
	var b strings.Builder
	for r := 0; r < rows; r++ {
		line := gutter
		for i, c := range cols {
			if i > 0 {
				line += strings.Repeat(" ", panelGap)
			}
			s := ""
			if r < len(c) {
				s = c[r]
			}
			// The last column is not padded out: trailing spaces cost width the
			// frame would then clip, turning a full-width row into a clipped one
			// for the sake of blanks nobody can see.
			if i < len(cols)-1 {
				s = pad(s, cell)
			}
			line += s
		}
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}
	return b.String()
}

// cut truncates to a width, counting columns rather than bytes.
//
// Plain text only, and that is deliberate: everything passed here is a title or
// a caption, styled AFTER cutting, so no escape sequence is ever split in half.
func cut(s string, w int) string {
	if lipglossWidth(s) <= w {
		return s
	}
	if w <= 1 {
		return ""
	}
	r := []rune(s)
	for len(r) > 0 && lipglossWidth(string(r))+1 > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}
