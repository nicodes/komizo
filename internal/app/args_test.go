package app

import (
	"strings"
	"testing"
)

// `komizo root @host` -- a space where there should not be one.
//
// The shell splits that into two arguments, the first is taken as the whole
// host, and the second is left over. The address was typed correctly and
// separated by one keystroke, so the answer is to say that rather than to print
// the usage: thirty lines that do not mention the problem, at somebody who
// typed almost the right thing.

func TestASplitAddressIsNamedRatherThanAnsweredWithTheUsage(t *testing.T) {
	// splitAddress is the shape run.go checks: a leftover starting with "@",
	// and a first argument that carries no "@" of its own.
	for _, tc := range []struct {
		host, rest string
		want       bool
	}{
		{"root", "@box.example.com", true},
		{"deploy", "@10.0.0.4", true},
		// Already a whole address: a second argument is a real mistake, not a
		// space, and deserves the usage.
		{"root@box.example.com", "@other", false},
		// Not the split-address shape at all.
		{"root@box.example.com", "extra", false},
		{"root", "extra", false},
	} {
		got := strings.HasPrefix(tc.rest, "@") && !strings.Contains(tc.host, "@")
		if got != tc.want {
			t.Errorf("komizo %s %s: detected=%v, want %v", tc.host, tc.rest, got, tc.want)
		}
	}
}

// The suggestion has to be the thing you can paste back.
func TestTheSuggestionRejoinsTheAddress(t *testing.T) {
	host, rest := "root", "@komizo.example.com"
	if got := host + rest; got != "root@komizo.example.com" {
		t.Errorf("suggestion = %q, want the two halves joined", got)
	}
}
