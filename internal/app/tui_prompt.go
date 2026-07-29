package app

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Asking, without going anywhere.
//
// Every question used to be a screen: the list vanished, a page of prose
// appeared, and answering it put the list back. That is a lot of ceremony for
// "are you sure", and it costs the one thing that makes the answer easy --
// seeing the row you are talking about while you decide. A prompt that replaces
// the help lines keeps the whole page in view and puts the question where your
// eyes already are for the key hints.
//
// Four shapes, because there are four kinds of question worth asking:
//
//	confirm    y/n. For anything reversible, or merely disruptive.
//	typeWord   type the name. For anything that deletes data -- a keypress is
//	           too easy to hit by accident, and this is the one guard that
//	           cannot be passed by reflex.
//	input      edit a value. For a setting rather than a decision.
//	form       several fields. For the one question that needs more than one
//	           answer, which is adding an app.
//	running    not a question: an operation in flight, with a spinner. Keys do
//	           nothing until it comes back.
//	result     what it produced, when it produced something worth keeping --
//	           the two values a new app needs pasted into GitHub.
//
// The form was a screen of its own until it was not. Adding an app is the same
// kind of act as the other four -- you are on the list, you want something to
// happen to it -- and it was the only one that blanked the page to ask. The
// three fields fit under the rule as easily as one does, and keeping the list
// behind them means the names already on the box stay visible while you type a
// new one, which is exactly when that matters.
type promptKind int

const (
	promptConfirm promptKind = iota
	promptTypeWord
	promptInput
	promptForm
	promptRunning
	promptResult
)

// startOp puts an operation in the footer and leaves the page behind it alone.
//
// This used to be two screens. Pressing "add" or "rotate" or "remove" blanked
// the list, streamed a few hundred lines of apk and docker output, and ended on
// a page of results -- for operations whose interesting part is the last four
// lines. The output was never the point: it was there because the operation had
// taken the screen and something had to fill it.
//
// So the footer does both halves. A spinner and a title while it runs, and then
// either the values it produced, or an error, or nothing at all -- which is
// what "it worked" looks like for a remove.
//
// The output is still collected. It is just not shown unless something fails.
func (m *model) startOp(title string) tea.Cmd {
	return m.withSpin(func() {
		m.run = newRunState(title)
		m.prompt = &prompt{kind: promptRunning, question: title}
		m.status, m.statusErr = "", false
	})
}

// running reports whether an operation is in flight, which is when the keys
// stop working and ctrl+c stops quitting.
func (m model) running() bool {
	return m.prompt != nil && m.prompt.kind == promptRunning
}

type prompt struct {
	kind     promptKind
	question string
	// detail is the consequence, in a sentence or two. Deliberately not a page:
	// the footer is not a place for prose, and a question that needs more than
	// this is usually one being asked too late.
	detail string

	word  string // typeWord: what must be typed
	typed string // typeWord and input: what has been

	check   func(string) error // input: rejects a bad value before it is used
	problem string
	action  func(*model, string) tea.Cmd
}

// ask puts a question in the footer. Nothing else changes: the list, the box
// and the proxy stay exactly where they were.
func (m model) ask(p prompt) model {
	m.prompt = &p
	m.status, m.statusErr = "", false
	return m
}

// answered reports whether the prompt is satisfied and enter should act.
func (p prompt) answered() bool {
	switch p.kind {
	case promptTypeWord:
		return p.typed == p.word
	case promptInput:
		return p.check == nil || p.check(strings.TrimSpace(p.typed)) == nil
	}
	return true
}

func (m model) handlePromptKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := m.prompt
	switch p.kind {
	// A form keeps its own state on the model -- several fields, one focused --
	// so it cannot be driven by the single "typed" string the others share.
	case promptForm:
		return m.handleFormKey(msg)

	// Nothing to press. The operation is on the server and will come back when
	// it comes back; the only key that does anything is ctrl+c, and update
	// refuses that too rather than abandon a half-applied change.
	case promptRunning:
		return m, nil

	case promptResult:
		return m.handleResultKey(msg)
	}
	switch msg.String() {
	case "esc":
		m.prompt = nil
		return m, nil

	case "enter":
		if !p.answered() {
			// An input says why; a half-typed name says nothing, because the
			// remaining letters are the message.
			if p.kind == promptInput {
				p.problem = p.check(strings.TrimSpace(p.typed)).Error()
			}
			return m, nil
		}
		value := strings.TrimSpace(p.typed)
		act := p.action
		m.prompt = nil
		// Sequenced rather than written as `return m, act(&m, value)`. The
		// action mutates m through that pointer, and Go does not specify
		// whether the returned copy is read before or after the call -- so the
		// spinner and busy flags an action sets could be present or lost at the
		// compiler's discretion. It happened to work, which is the worst way
		// for it to work.
		cmd := act(&m, value)
		return m, cmd

	case "backspace":
		if p.kind != promptConfirm && p.typed != "" {
			p.typed = trimLastRune(p.typed)
			p.problem = ""
		}
		return m, nil

	case "y", "Y":
		// Only where a single key is the whole answer. In the other two shapes
		// "y" is a letter, and swallowing it would make "my-app" untypeable.
		if p.kind == promptConfirm {
			act := p.action
			m.prompt = nil
			cmd := act(&m, "")
			return m, cmd
		}
	}

	if p.kind != promptConfirm {
		if s := typedText(msg); s != "" {
			p.typed += s
			p.problem = ""
		}
	}
	return m, nil
}

// promptView renders whatever is being asked, in place of the key hints.
//
// A method on the model rather than on the prompt, because a form's fields live
// on the model: the prompt says which question is open, and m.form is the
// half-typed answer to it.
func (m model) promptView() string {
	p := m.prompt
	switch p.kind {
	case promptRunning:
		return "\n" + gutter + spinner(m.spin) + " " +
			titleStyle.Render(p.question) + "\n"

	case promptResult:
		// A failure keeps the last few lines of output. It is the only place
		// they are ever shown, and "exit status 1" on its own diagnoses nothing.
		if m.run.err != nil {
			var b strings.Builder
			b.WriteString("\n" + gutter + dot("err") + " " +
				errStyle.Render(title(m.run.title)+" failed") + "\n")
			for _, ln := range wrap(m.run.err.Error(), textWidth(m.width)) {
				b.WriteString(gutter + dimStyle.Render(ln) + "\n")
			}
			if tail := m.run.tail(4); len(tail) > 0 {
				b.WriteString("\n")
				for _, ln := range tail {
					b.WriteString(gutter + dimStyle.Render(ln) + "\n")
				}
			}
			return b.String() + helpLine(m.width, "enter", "dismiss")
		}
		if m.run.result == nil {
			return ""
		}
		return "\n" + m.run.result.view() +
			helpLine(m.width, "↑↓", "select", "c", "copy", "enter", "done")

	case promptForm:
	default:
		return p.view(m.width)
	}

	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render(p.question) + "\n")
	for _, ln := range wrap(p.detail, textWidth(m.width)) {
		b.WriteString(gutter + dimStyle.Render(ln) + "\n")
	}
	b.WriteString("\n" + renderFields(m.form.fields, m.form.focus))
	b.WriteString(problemLines(m.form.problem, m.width))
	return b.String() + helpLine(m.width,
		"tab", "next field", "enter", "add it", "esc", "cancel")
}

// handleResultKey drives the values an operation left behind.
//
// Both have to reach GitHub, so both are selectable and both are copyable.
// Copying one does not finish the job, which is why each keeps its own tick.
func (m model) handleResultKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	r := m.run.result
	if r == nil {
		m.prompt = nil
		return m, nil
	}
	switch msg.String() {
	case "up":
		if r.cursor > 0 {
			r.cursor--
		}
	case "down":
		if r.cursor < r.items()-1 {
			r.cursor++
		}
	case "c":
		if err := r.copySelected(); err != nil {
			r.copyErr, r.onClipboard = err.Error(), -1
		} else {
			// Replaces, never accumulates: whatever was there is gone.
			r.onClipboard, r.copyErr = r.cursor, ""
		}
	case "enter", "esc", "q":
		// No read on the way out. The operation asked for one when it finished,
		// and the poll has been running the whole time this was on screen --
		// dismissing a result changes nothing on the server.
		m.prompt = nil
	}
	return m, nil
}

// problemLines is why the value was rejected, wrapped.
//
// Wrapped rather than left to run off the edge: every row is clipped to the
// window now, so a long message used to lose its end -- and the end of a
// validation message is usually the part naming what was wrong.
func problemLines(problem string, width int) string {
	if problem == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, ln := range wrap(problem, textWidth(width)) {
		b.WriteString(gutter + errStyle.Render(ln) + "\n")
	}
	return b.String()
}

// view renders the prompt in place of the key hints.
func (p prompt) view(width int) string {
	var b strings.Builder
	// No status glyph, and no indent under it.
	//
	// A dot is how this page says what state a thing is in; a question is not a
	// state, and colouring it amber made every prompt look like a warning --
	// including "Config image for blog", which is a setting. The footer is
	// already fenced off by a rule and is the only interactive part of the
	// page, so it needs no second marker to be found.
	b.WriteString("\n" + gutter + titleStyle.Render(p.question) + "\n")
	// Wrapped, not truncated: the consequence is the whole reason the question
	// is worth asking, and a terminal narrower than the sentence is normal.
	for _, ln := range wrap(p.detail, textWidth(width)) {
		b.WriteString(gutter + dimStyle.Render(ln) + "\n")
	}

	switch p.kind {
	case promptConfirm:
		b.WriteString(help("y", "yes", "esc", "cancel"))

	case promptTypeWord:
		typed := p.typed
		if p.answered() {
			typed = okStyle.Render(typed)
		}
		b.WriteString(fmt.Sprintf("\n"+gutter+"type %s to confirm  %s%s\n",
			keyStyle.Render(p.word), typed, barStyle.Render("▏")))
		if p.answered() {
			b.WriteString(help("enter", "do it", "esc", "cancel"))
		} else {
			b.WriteString(help("esc", "cancel"))
		}

	case promptInput:
		b.WriteString("\n" + gutter + p.typed + barStyle.Render("▏") + "\n")
		b.WriteString(problemLines(p.problem, width))
		b.WriteString(help("enter", "save", "esc", "cancel"))
	}
	return b.String()
}
