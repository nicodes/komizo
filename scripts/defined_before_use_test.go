package scripts

import (
	"regexp"
	"strings"
	"testing"
)

// EVERY FUNCTION IS DEFINED BEFORE IT IS CALLED.
//
// Shell does not hoist. A script that calls a function declared further down
// dies at that line with "not found", and it dies at RUN time on somebody's
// server -- not in `sh -n`, which checks syntax and is happy with it.
//
// It happened. nicodes/komizo-be#164 added komizo_sshd_conf_is_ours inside the
// sshd-validation block and called it from the section ABOVE, under a comment
// that said "defined further down" as though that were fine. `komizo add`
// against a real box created the deploy account, the app directory, the deploy
// scripts and the doas rules, and then:
//
//	sh: komizo_sshd_conf_is_ours: not found
//
// Two of the three scripts had it. The one test that exercised the function
// extracted the block and appended the call AFTER it -- an order the real
// script never runs in -- so it was green on both.
//
// This reads the scripts as they SHIP, in order, which is the only reading that
// can see it.

// A call is a bare word at the start of a command. Definitions are `name() {`.
var (
	shellDef  = regexp.MustCompile(`(?m)^(\w+)\(\)\s*\{`)
	shellWord = regexp.MustCompile(`^[a-z_][a-z0-9_]*`)
)

func TestEveryShellFunctionIsDefinedBeforeItIsCalled(t *testing.T) {
	checked := 0
	for name, src := range all(t) {
		defs := map[string]int{}
		for _, m := range shellDef.FindAllStringSubmatchIndex(src, -1) {
			fn := src[m[2]:m[3]]
			if _, seen := defs[fn]; !seen {
				defs[fn] = strings.Count(src[:m[0]], "\n") + 1
			}
		}
		if len(defs) == 0 {
			continue
		}
		checked++

		for n, ln := range strings.Split(src, "\n") {
			line := n + 1
			code := ln
			// Comments are prose. The bug this exists for was DESCRIBED in one.
			if i := strings.Index(code, "#"); i >= 0 {
				code = code[:i]
			}
			trimmed := strings.TrimSpace(code)
			// The word in command position, past the shell keywords that can
			// precede one. `if ! foo` and `then foo` both call foo.
			for _, kw := range []string{"if ", "! ", "then ", "else ", "elif ", "while ", "until ", "&& ", "|| ", "do "} {
				trimmed = strings.TrimPrefix(strings.TrimSpace(trimmed), kw)
			}
			word := shellWord.FindString(strings.TrimSpace(trimmed))
			if word == "" {
				continue
			}
			at, isFn := defs[word]
			if !isFn || at <= line {
				continue
			}
			// The definition line itself is not a call.
			if strings.Contains(ln, word+"()") {
				continue
			}
			t.Errorf("%s calls %s() at line %d and defines it at line %d -- shell does not "+
				"hoist, so this dies at run time on somebody's server with "+
				"\"%s: not found\"", name, word, line, at, word)
		}
	}
	if checked == 0 {
		t.Fatal("no script defined a shell function, so this checked nothing")
	}
}
