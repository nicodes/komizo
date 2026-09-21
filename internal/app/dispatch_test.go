package app

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// `komizo ui` shipped unreachable: RunUI existed, ui_test.go exercised it
// directly, CI was green -- and the binary answered `"ui" is not a command.`,
// because the command was in runCommand's switch but not in the outer argv
// router's case-list, which names the same commands a second time.
//
// Two switches, one set of commands, and nothing compared them. This does:
// both lists are read from the SOURCE, parsed rather than grepped (the same
// reading init_order_test.go makes, and for the same reason -- a comment
// naming a command cannot satisfy it), and then every name is DRIVEN through
// Main, because a source agreement the runtime does not honour is the bug
// this file exists to prevent, one level up.

// caseNames parses fn's switch and returns the string literals of the case
// clause whose body calls `callee` -- or, when callee is empty, of every case
// clause in the switch.
func caseNames(t *testing.T, fnName, callee string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != fnName || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			if callee != "" {
				callsIt := false
				for _, stmt := range cc.Body {
					ast.Inspect(stmt, func(n ast.Node) bool {
						if call, ok := n.(*ast.CallExpr); ok {
							if id, ok := call.Fun.(*ast.Ident); ok && id.Name == callee {
								callsIt = true
							}
						}
						return true
					})
				}
				if !callsIt {
					return true
				}
			}
			for _, expr := range cc.List {
				if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					out = append(out, v)
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// The router and the dispatcher are the same set. A command added to one and
// not the other is either unreachable (ui's bug) or a route to "unknown
// command", and neither is caught by anything but this.
func TestTheRouterAndTheDispatcherNameTheSameCommands(t *testing.T) {
	routed := caseNames(t, "Main", "runCommand")
	known := caseNames(t, "runCommand", "")
	if len(routed) == 0 || len(known) == 0 {
		t.Fatalf("the parse found nothing (routed %v, known %v) -- has run.go changed shape?", routed, known)
	}
	if strings.Join(routed, ",") != strings.Join(known, ",") {
		t.Errorf("the outer router routes %v but runCommand knows %v -- a command "+
			"named in exactly one of them is unreachable or 404s, which is how "+
			"`komizo ui` shipped dispatching to \"is not a command\"", routed, known)
	}
}

// And the runtime honours it: every routed command, driven through Main with
// a flag none of them defines, must reach its own FlagSet -- which answers
// ErrSilent after printing usage -- rather than the default branch's "is not
// a command". This exact drive was green-red on the merged tree: ui failed
// it, everything else passed.
func TestEveryRoutedCommandDispatches(t *testing.T) {
	for _, name := range caseNames(t, "Main", "runCommand") {
		err := Main([]string{name, "--definitely-not-a-flag"})
		if !errors.Is(err, ErrSilent) {
			t.Errorf("komizo %s = %v, want ErrSilent from its own flag parser -- "+
				"anything else means it never reached the command", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "is not a command") {
			t.Errorf("komizo %s fell through to the default branch", name)
		}
	}

	// The negative control, so the assertions above are known to be able to
	// fail: a name in neither list takes the default branch.
	err := Main([]string{"nosuchcmd"})
	if err == nil || !strings.Contains(err.Error(), "is not a command") {
		t.Errorf("komizo nosuchcmd = %v, want the not-a-command answer", err)
	}
}

// The bug itself, stated as behaviour: `komizo ui` reaches RunUI, which
// answers its own validation error -- never the router's refusal. A bad port
// is the probe because the good one starts a server.
func TestUIIsDispatchable(t *testing.T) {
	err := Main([]string{"ui", "--port", "0"})
	if err == nil || !strings.Contains(err.Error(), "--port must be") {
		t.Errorf("komizo ui --port 0 = %v, want RunUI's own port validation", err)
	}
}
