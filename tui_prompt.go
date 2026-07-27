package main

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
// Three shapes, because there are three kinds of question worth asking:
//
//	confirm    y/n. For anything reversible, or merely disruptive.
//	typeWord   type the name. For anything that deletes data -- a keypress is
//	           too easy to hit by accident, and this is the one guard that
//	           cannot be passed by reflex.
//	input      edit a value. For a setting rather than a decision.
type promptKind int

const (
	promptConfirm promptKind = iota
	promptTypeWord
	promptInput
)

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
		return m, act(&m, value)

	case "backspace":
		if p.kind != promptConfirm && p.typed != "" {
			p.typed = p.typed[:len(p.typed)-1]
			p.problem = ""
		}
		return m, nil

	case "y", "Y":
		// Only where a single key is the whole answer. In the other two shapes
		// "y" is a letter, and swallowing it would make "my-app" untypeable.
		if p.kind == promptConfirm {
			act := p.action
			m.prompt = nil
			return m, act(&m, "")
		}
	}

	if p.kind != promptConfirm {
		if s := msg.String(); len(s) == 1 {
			p.typed += s
			p.problem = ""
		}
	}
	return m, nil
}

// view renders the prompt in place of the key hints.
func (p prompt) view() string {
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
	for _, ln := range wrap(p.detail, 74) {
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
		if p.problem != "" {
			b.WriteString("\n" + gutter + errStyle.Render(p.problem) + "\n")
		}
		b.WriteString(help("enter", "save", "esc", "cancel"))
	}
	return b.String()
}
