package app

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Setting a server up files it under an account -- from BOTH surfaces.
//
// This shipped working from `komizo init` and not from the interface, which is
// the surface most people use. The capability was written for one and the other
// was never given it, so a box set up from the interface never appeared in the
// app and there was nothing on screen to say why.
//
// A test that reads the source rather than runs it, because the alternative is
// standing up a service and a box to prove a function is called. What is being
// guarded here is not behaviour under load, it is somebody adding a third
// setup path and giving it to one surface again.

func sourceOf(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEverySetupPathRegistersTheServer(t *testing.T) {
	// The two ways a fresh box gets set up: the subcommand, and the interface's
	// start button.
	for _, tc := range []struct{ file, fn string }{
		{"init.go", "RunInit"},
		{"tui_ops.go", "startInit"},
	} {
		src := sourceOf(t, tc.file)
		body := functionBody(t, src, tc.fn)
		if !strings.Contains(body, "registerAndEnrol") {
			t.Errorf("%s in %s sets a box up without filing it under an account -- "+
				"a server set up this way never appears in the app", tc.fn, tc.file)
		}
	}
}

// Both surfaces install the agent too, which is the other thing a box is not
// usable without. Same failure shape, and it has happened once already.
func TestEverySetupPathInstallsTheAgent(t *testing.T) {
	for _, tc := range []struct{ file, fn, want string }{
		{"init.go", "RunInit", "installAgent"},
		{"tui_ops.go", "startInit", "streamAgent"},
	} {
		src := sourceOf(t, tc.file)
		body := functionBody(t, src, tc.fn)
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s in %s does not install the agent", tc.fn, tc.file)
		}
	}
}

// Registering must never fail the setup. The box is set up and works; what
// failed is the half that needs the service, and failing the whole command
// would make an outage look like a broken server.
func TestRegisteringIsNotFatalToSetup(t *testing.T) {
	for _, tc := range []struct{ file, fn string }{
		{"init.go", "RunInit"},
		{"tui_ops.go", "startInit"},
	} {
		body := functionBody(t, sourceOf(t, tc.file), tc.fn)
		i := strings.Index(body, "registerAndEnrol")
		if i < 0 {
			continue // the test above already reports this
		}
		// The eight lines after the call decide it: a `return` there ends the
		// setup, and anything else carries on.
		rest := body[i:]
		if cut := strings.Index(rest, "\n\n"); cut > 0 {
			rest = rest[:cut]
		}
		if regexp.MustCompile(`(?m)^\s*(return|ch <- runDoneMsg\{err)`).MatchString(rest) {
			t.Errorf("%s in %s abandons setup when registering fails:\n%s", tc.fn, tc.file, rest)
		}
	}
}

// functionBody is the text between a function's opening brace and the closing
// one in column zero.
func functionBody(t *testing.T, src, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func (\([^)]*\) )?` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("could not find func %s", name)
	}
	rest := src[loc[0]:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}
