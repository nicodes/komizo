package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Setting a server up files it under an account, and installs the agent.
//
// This shipped working from `komizo init` and not from the interface, which was
// then the surface most people used: the capability was written for one and the
// other was never given it, so a box set up from the interface never appeared in
// the app and there was nothing on screen to say why.
//
// THE SECOND SURFACE IS GONE (nicodes/komizo-be#55) and this file is not,
// because the failure it caught was never really about having two surfaces. It
// was about a second code path to the same operation, written by somebody who
// did not know the first one had a step in it. `komizo update` is that second
// path today.
//
// So this no longer takes a hardcoded list of paths -- a list is what let the
// original bug through, since the interface's path was simply not on it. It
// FINDS every function that provisions a box and holds each one to the rules.

// setupPaths is every function in this package that runs the provisioning
// script, found rather than listed.
//
// go/ast rather than a grep: a grep over the source counts the constant's name
// wherever it appears, including in a comment saying a function does not run it,
// and cannot tell which function it appeared inside.
func setupPaths(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]*ast.FuncDecl{}
	for _, p := range pkg {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "AlpineInitScript" {
						return true
					}
					// `komizo script init` PRINTS the script rather than
					// running it, which is the one legitimate mention that is
					// not a setup path.
					if isPrintArg(fn, sel) {
						return true
					}
					found[fn.Name.Name] = fn
					return true
				})
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("no function in this package runs the provisioning script -- " +
			"either setup moved or this test stopped being able to find it")
	}
	return found
}

// isPrintArg reports whether the script is being handed to fmt.Print rather than
// to a runner.
func isPrintArg(fn *ast.FuncDecl, target *ast.SelectorExpr) bool {
	printed := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.HasPrefix(sel.Sel.Name, "Print") {
			return true
		}
		for _, a := range call.Args {
			if a == target {
				printed = true
			}
		}
		return true
	})
	return printed
}

// calls reports whether a function's body calls the named function anywhere.
func calls(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if ok && id.Name == name {
			found = true
		}
		return true
	})
	return found
}

// THE SET ITSELF IS PINNED, so a third path cannot be added quietly.
//
// Every rule below is "each path must also do X", and a rule of that shape is
// satisfied vacuously by a path nobody added to the list -- which is precisely
// how the original bug shipped. This one fails on a NEW path, and the fix is to
// come here and decide which rules it is under.
func TestTheSetupPathsAreTheOnesWeKnowAbout(t *testing.T) {
	var got []string
	for name := range setupPaths(t) {
		got = append(got, name)
	}
	sort.Strings(got)
	want := "RunInit, RunUpdate"
	if strings.Join(got, ", ") != want {
		t.Errorf("functions that provision a box = %q, want %q -- a new one has to be "+
			"held to the rules below rather than added here", strings.Join(got, ", "), want)
	}
}

// EVERY setup path installs the agent. A box without one is set up and unusable:
// nothing reports, so nothing about it can be read or commanded.
func TestEverySetupPathInstallsTheAgent(t *testing.T) {
	for name, fn := range setupPaths(t) {
		if !calls(fn, "installAgent") {
			t.Errorf("%s provisions a box without installing the agent -- "+
				"nothing on that box would ever report", name)
		}
	}
}

// A FRESH box is filed under an account. `komizo update` is exempt and must be:
// it runs against a box that is already set up, and re-registering one would be
// how a second row with the same name appears in somebody's app.
func TestSettingUpAFreshBoxRegistersIt(t *testing.T) {
	fn, ok := setupPaths(t)["RunInit"]
	if !ok {
		t.Fatal("RunInit no longer provisions a box, so nothing here is guarding setup")
	}
	if !calls(fn, "registerAndEnrol") {
		t.Error("RunInit sets a box up without filing it under an account -- " +
			"a server set up this way never appears in the app")
	}
	if u, ok := setupPaths(t)["RunUpdate"]; ok && calls(u, "registerAndEnrol") {
		t.Error("RunUpdate registers the box it is updating -- a box that has " +
			"already enrolled would get a second row in somebody's app")
	}
}

// Registering must never fail the setup. The box is set up and works; what
// failed is the half that needs the service, and failing the whole command
// would make an outage look like a broken server.
func TestRegisteringIsNotFatalToSetup(t *testing.T) {
	body := functionBody(t, sourceOf(t, "init.go"), "RunInit")
	i := strings.Index(body, "registerAndEnrol")
	if i < 0 {
		t.Skip("the test above already reports this")
	}
	// The lines up to the next blank one decide it: a `return` there ends the
	// setup, and anything else carries on.
	rest := body[i:]
	if cut := strings.Index(rest, "\n\n"); cut > 0 {
		rest = rest[:cut]
	}
	if regexp.MustCompile(`(?m)^\s*return`).MatchString(rest) {
		t.Errorf("RunInit abandons setup when registering fails:\n%s", rest)
	}
}

func sourceOf(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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

// Enrolling a box that has already enrolled must not leave a second server
// behind.
//
// It did, and the result was two rows with the same name in somebody's app --
// one reporting, one that never would again, and nothing on either to say
// which. Found by enrolling the same box twice while checking something else.
func TestEnrollingTwiceReusesTheServerItIsAlreadyFiledUnder(t *testing.T) {
	body := functionBody(t, sourceOf(t, "init.go"), "registerAndEnrol")

	if strings.Contains(body, "createServer(ctx, s, name)") {
		t.Error("registerAndEnrol creates a server unconditionally -- a box that has " +
			"enrolled before would get a second row")
	}
	if !strings.Contains(body, "reuseOrCreate") {
		t.Error("registerAndEnrol does not ask whether this box is already filed under a server")
	}

	// And the reuse path has to read the id from the BOX, because this machine
	// is not the only thing that ever enrols it.
	reuse := functionBody(t, sourceOf(t, "init.go"), "reuseOrCreate")
	if !strings.Contains(reuse, "existingServerID") {
		t.Error("reuseOrCreate does not read the id the box already holds")
	}
	if !strings.Contains(reuse, "createServer") {
		t.Error("reuseOrCreate cannot fall back to creating one, so a fresh box could not enrol")
	}
}
