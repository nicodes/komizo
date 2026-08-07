package box

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// EVERY ROUTE THIS BOX SERVES, AND WHAT STANDS IN FRONT OF IT.
//
// Review 1 on komizo#75 asked the right question about the tests that came with
// komizo-be#72: they pin two literal paths. Adding a token-only `GET /v1/status`
// that serves the whole report left the entire suite green -- the hole was
// closed at `/v1/report` and `/v1/history` and nowhere else, which is a fact
// about two strings rather than about this box.
//
// So this reads the routes out of Handler() and requires each one to name its
// guard HERE. A route added without an entry fails; a route whose guard is
// removed fails; a route that changes which guard it uses fails. Nothing about
// it depends on knowing what the new route is called.
//
// WHY A SOURCE CHECK. http.ServeMux does not enumerate its patterns, so there is
// nothing to ask at runtime. The behavioural tests beside this one drive the
// routes that exist; this one is about the routes somebody adds next.
func TestEveryRouteNamesItsGuard(t *testing.T) {
	// The guard each pattern is allowed to rely on, and why anything short of a
	// verified envelope is acceptable.
	want := map[string]string{
		// A device signed for exactly this op. The two reads komizo-be#72 shut.
		"POST /v1/report":  "verifiedRead",
		"POST /v1/history": "verifiedRead",

		// serveLog does its own verification, including the 403/409 split -- see
		// logs.go. It is a read of somebody's application output and is held to
		// the same bar as the two above.
		"POST /v1/logs": "serveLog",

		// postCommand verifies the envelope before anything is claimed; the
		// signature is the authority and the token is only transport.
		"POST /v1/commands": "postCommand",

		// TOKEN AND AN ID, DELIBERATELY, and the one route here that is not
		// behind a signature. The id is minted by a command that WAS verified
		// and is returned only to whoever sent it, so this asks "what happened
		// to the thing I signed" rather than "tell me about this box". Reading
		// it needs the id, which nothing else discloses.
		"GET /v1/commands/{id}": "getResult",

		// Everything else, including an unknown path, is refused with exactly
		// what an unauthorized request gets.
		"/": "refuse",
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "api.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("could not parse api.go: %v", err)
	}

	got := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}

		// Every function this handler calls, so the guard is found wherever in
		// the body it sits.
		var calls []string
		ast.Inspect(call.Args[1], func(m ast.Node) bool {
			if c, ok := m.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok {
					calls = append(calls, id.Name)
				}
			}
			return true
		})
		got[pattern] = strings.Join(calls, ",")
		return true
	})

	// A route registered somewhere this cannot see is worse than a route with
	// the wrong guard, because it looks like nothing at all.
	if len(got) == 0 {
		t.Fatal("no mux.HandleFunc calls were found in api.go -- the routes moved, and this " +
			"check is now reading a file that registers nothing")
	}

	for pattern, calls := range got {
		guard, known := want[pattern]
		if !known {
			t.Errorf("api.go serves %q and nothing here says what guards it.\n"+
				"  Add it above WITH THE REASON. If it reads anything about this box, it needs a\n"+
				"  verified envelope -- komizo-be#72 removed the last route that did not have one.\n"+
				"  It calls: %s", pattern, calls)
			continue
		}
		if !strings.Contains(","+calls+",", ","+guard+",") {
			t.Errorf("%q is supposed to be guarded by %s() and does not call it.\n  It calls: %s",
				pattern, guard, calls)
		}
	}
	for pattern := range want {
		if _, served := got[pattern]; !served {
			t.Errorf("this check expects %q to be served and api.go does not register it -- "+
				"either the route was removed and this entry should go, or it moved somewhere "+
				"this cannot see", pattern)
		}
	}

	// AND THE TWO READS ARE STILL POST-ONLY. The whole of komizo-be#72 is that
	// no method on these paths reads without a signature, and a `GET /v1/report`
	// added back would be a new pattern this loop reports -- but only if
	// somebody reads the failure as being about the method. Said explicitly.
	for pattern := range got {
		if strings.HasSuffix(pattern, "/v1/report") || strings.HasSuffix(pattern, "/v1/history") {
			if !strings.HasPrefix(pattern, "POST ") {
				t.Errorf("%q serves a read on a method other than POST, so it cannot be carrying "+
					"a signed envelope", pattern)
			}
		}
	}
}
