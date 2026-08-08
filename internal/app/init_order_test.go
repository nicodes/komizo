package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// The proxy is installed BEFORE the box enrols, and swapping them back has to
// fail here.
//
// It was the other way round, and the consequence was not a rare race: on every
// fresh box, every time, `komizo init` published no route for the box's own
// name. agent-enrol.sh writes that route only when /srv/_proxy/routes exists,
// and the proxy script is what creates it -- so the guard was false on every
// first run, the route was skipped in silence, and the box came up enrolled,
// reporting, and unreachable at its own hostname.
//
// NOTHING COULD HAVE CAUGHT THAT. The two steps are in different languages: the
// dependency lives in a shell guard on the box and the ordering lives in a Go
// function on the laptop, and neither file mentions the other. Every test of
// enrolment ran against a fixture, where the directory either exists or is
// irrelevant, so all of them passed against the broken order.
//
// So this reads the ORDER OF THE STATEMENTS, from the source as it ships, which
// is the one place the fact actually lives. Parsed rather than grepped, so a
// comment naming either step cannot satisfy it -- this whole comment names both.
func TestInitInstallsTheProxyBeforeItEnrols(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "init.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var body []ast.Stmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "RunInit" && fn.Body != nil {
			body = fn.Body.List
		}
	}
	if body == nil {
		// The function was renamed or moved. Fail rather than skip: a test that
		// quietly stops looking at anything is the failure this file exists to
		// prevent, one level up.
		t.Fatal("RunInit is not in init.go any more, so nothing here is checking the order")
	}

	proxy, enrol := -1, -1
	for i, stmt := range body {
		var names []string
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				names = append(names, v.Name)
			case *ast.SelectorExpr:
				names = append(names, v.Sel.Name)
			}
			return true
		})
		for _, n := range names {
			if n == "AlpineProxyScript" && proxy < 0 {
				proxy = i
			}
			if n == "registerAndEnrol" && enrol < 0 {
				enrol = i
			}
		}
	}

	if proxy < 0 {
		t.Fatal("RunInit no longer installs the proxy")
	}
	if enrol < 0 {
		t.Fatal("RunInit no longer enrols the box")
	}
	if proxy > enrol {
		t.Errorf("RunInit enrols at statement %d and installs the proxy at %d.\n"+
			"agent-enrol.sh publishes this box's route only if /srv/_proxy/routes exists,\n"+
			"and the proxy script is what creates it -- so in this order the route is\n"+
			"skipped on every fresh box and the app cannot reach it by name.", enrol, proxy)
	}
}

// And the skip is audible.
//
// The ordering above is the fix; this is what would have found it. A guard that
// declines to do something and says nothing is indistinguishable from a guard
// that did it -- which is how this survived a release, an app screen, and two
// rounds of blaming DNS.
func TestEnrolmentSaysSoWhenItCannotPublishTheRoute(t *testing.T) {
	// The rendered script, as the box receives it, so a placeholder that swallowed
	// the guard would show up here rather than in production.
	s := scripts.AgentEnrol("https://api.example.com", "kmz_enr_x", "box.example.com", nil, false)
	// The guard and the warning are a pair. Asserting only the text would pass
	// on a script that warns and then writes nothing either way.
	if !strings.Contains(s, "[ ! -d /srv/_proxy/routes ]") {
		t.Error("agent-enrol.sh no longer notices that the proxy is missing")
	}
	if !strings.Contains(s, "was not published") {
		t.Error("agent-enrol.sh skips the route without saying so, which is how this was missed")
	}
}
