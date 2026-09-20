package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On-demand TLS is gated behind EXPLICIT demand: --tls-ask applies to the
// run that passes it and is carried nowhere. The carry-forward added in
// komizo#132 (a per-box proxy.json, re-emitted on flagless re-runs) was
// removed once no active route on any box used on-demand issuance -- the
// fail-closed guard in alpine-proxy.sh is what keeps a gated box safe, and
// explicit demand is one flag away if a product needs it again. These are
// the inverse of #132's persistence suite: absence, asserted, so the
// carry-forward cannot quietly come back.

// Nothing in the CLI may read or write proxy state for tls-ask. A source
// assertion, because the behaviour under test IS an absence: there is no
// longer a function to call and get the wrong answer from, so what is pinned
// is that the mechanism itself is gone -- a reintroduced proxy.json reader
// or writer fails here, wherever it is added.
func TestNoProxyStateIsCarriedForTLSAsk(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no package sources found: %v", err)
	}
	for _, f := range sources {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, gone := range []string{"proxy.json", "proxyState", "resolveTLSAsk"} {
			if strings.Contains(string(b), gone) {
				t.Errorf("%s mentions %q -- tls-ask is explicit per run and carried in no state file", f, gone)
			}
		}
	}
}

// The flag itself stays, and so does its validation: a run that passes
// --tls-ask explicitly gets the gate for that run, constrained to an
// http(s) URL before it is interpolated into the server's Caddyfile.
func TestTheExplicitFlagStillValidates(t *testing.T) {
	for _, ok := range []string{
		"",
		"http://localhost:8080/ask",
		"https://gate.example.com/ask?name=~&a=b-c_d.e",
	} {
		if err := validateTLSAsk(ok); err != nil {
			t.Errorf("validateTLSAsk(%q) refused a value it should carry: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"not-a-url",
		"ftp://gate.example.com/ask",
		"https://gate.example.com/ask with space",
		"https://gate.example.com/$(whoami)",
	} {
		if err := validateTLSAsk(bad); err == nil {
			t.Errorf("validateTLSAsk(%q) accepted a value that must never reach the Caddyfile", bad)
		}
	}
}

// A stale proxy.json left behind by a #132-era CLI is inert: the flagless
// path is the flag default, and nothing consults the file. Pinned as an
// observation about the package rather than a run of RunProxy, which needs
// a server -- TestNoProxyStateIsCarriedForTLSAsk is what keeps it true.
func TestAStaleProxyStateFileChangesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "komizo"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := `{"tlsAsk":{"box.example.com":"https://gate.example.com/ask"}}`
	if err := os.WriteFile(filepath.Join(dir, "komizo", "proxy.json"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	// The session beside it must still read, proving the shared config dir
	// is untouched by the removal.
	if _, err := readSession(); err != nil {
		t.Errorf("a stale proxy.json broke the state that remains: %v", err)
	}
}
