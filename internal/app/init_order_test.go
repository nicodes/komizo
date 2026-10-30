package app

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// SSH bootstrap must retain the proxy and make no hosted registration call.
func TestInitInstallsTheProxyAndDoesNotRegister(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "init.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var body []ast.Stmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "runInit" && fn.Body != nil {
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
	if enrol >= 0 {
		t.Errorf("RunInit registers the box at statement %d -- the service is decommissioned,\n"+
			"so that statement is a network request to nothing on every init. The\n"+
			"registration tail was removed deliberately; do not put it back.", enrol)
	}
}

func TestInitRefusesRetiredRegistrationFlags(t *testing.T) {
	for _, args := range [][]string{{"--name", "unused"}, {"--api-host", "example.invalid"}, {"--device-key", "unused"}, {"--forget-devices"}} {
		if err := RunInit(args); !errors.Is(err, ErrSilent) {
			t.Fatalf("retired registration flag %s was not refused before connection: %v", args[0], err)
		}
	}
}
