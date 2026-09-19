package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// alpine-proxy.sh runs as root and owns the one config every site on a box
// loads, so -- like deploy-<app> in deploy_script_test.go -- it is tested by
// running it, not by parsing it. Docker, chown and id are stubbed; what is
// being tested is the part komizo wrote: when a Caddyfile is written, what
// it contains, and when the script refuses and writes nothing.

// proxyBox is a fake server for the proxy script: a proxy directory with its
// routes, and a PATH where docker does as it is told.
type proxyBox struct {
	root, proxyDir, routes, bin string
	script                      string
}

func newProxyBox(t *testing.T) *proxyBox {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	root := t.TempDir()
	b := &proxyBox{
		root:     root,
		proxyDir: filepath.Join(root, "srv", "_proxy"),
		bin:      filepath.Join(root, "bin"),
	}
	b.routes = filepath.Join(b.proxyDir, "routes")
	for _, d := range []string{b.routes, b.bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// The test does not run as root, and the script chowns what it writes and
	// refuses to run for anybody else.
	write(t, filepath.Join(b.bin, "id"), 0o755, "#!/bin/sh\necho 0\n")
	write(t, filepath.Join(b.bin, "chown"), 0o755, "#!/bin/sh\nexit 0\n")
	// Nothing here tests Docker. Every call -- network inspect, compose
	// config, compose up, the caddy validate inside the container -- answers
	// success, so a run gets as far as the script's own logic lets it.
	write(t, filepath.Join(b.bin, "docker"), 0o755, "#!/bin/sh\nexit 0\n")

	// The shipped script, pointed at this fake box rather than at /srv and
	// /run -- the same substitution deploy_script_test makes for alpine.sh.
	b.script = strings.NewReplacer(
		"/srv/_proxy", b.proxyDir,
		"/run/komizo", filepath.Join(root, "run", "komizo"),
	).Replace(scripts.AlpineProxyScript)
	return b
}

func (b *proxyBox) run(t *testing.T, tlsAsk string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(b.script)
	cmd.Env = append(os.Environ(),
		"PATH="+b.bin+":/usr/bin:/bin",
		"TLS_ASK="+tlsAsk,
		"API_SOCKET_DIR="+filepath.Join(b.root, "run", "komizo", "api"),
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (b *proxyBox) caddyfile(t *testing.T) string {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(b.proxyDir, "Caddyfile"))
	if err != nil {
		return ""
	}
	return string(got)
}

// The September incident, stated as behaviour: a re-run without --tls-ask on
// a box whose routes still need on-demand issuance must write NOTHING. That
// run rewrote the Caddyfile without the gate, caddy validate refused the
// whole config, and one restart would have taken every app on the box dark.
func TestAnOnDemandRouteWithoutAGateIsRefused(t *testing.T) {
	b := newProxyBox(t)
	route := filepath.Join(b.routes, "blog.caddy")
	write(t, route, 0o644, "*.blog.example.com {\n\ttls {\n\t\ton_demand\n\t}\n\treverse_proxy blog-gate:80\n}\n")
	gated := "{\n\ton_demand_tls {\n\t\task https://localhost/ask\n\t}\n}\nimport /etc/caddy/routes/*.caddy\n"
	write(t, filepath.Join(b.proxyDir, "Caddyfile"), 0o644, gated)

	out, err := b.run(t, "")
	if err == nil {
		t.Fatalf("an on-demand route with no gate was rewritten anyway:\n%s", out)
	}
	if !strings.Contains(out, "--tls-ask") {
		t.Errorf("the refusal does not name the fix:\n%s", out)
	}
	if !strings.Contains(out, "blog.caddy") {
		t.Errorf("the refusal does not name the route that needs the gate:\n%s", out)
	}
	if got := b.caddyfile(t); got != gated {
		t.Errorf("the Caddyfile was touched by a run that should have written nothing:\n%s", got)
	}
	if _, statErr := os.Stat(filepath.Join(b.proxyDir, "compose.yml")); statErr == nil {
		t.Error("the compose file was written by a run that should have written nothing")
	}
}

// The refusal is about on-demand routes, not about running gateless: a box
// with no wildcard anywhere gets its plain Caddyfile as before.
func TestAPlainRouteWithoutAGateIsWritten(t *testing.T) {
	b := newProxyBox(t)
	write(t, filepath.Join(b.routes, "blog.caddy"), 0o644,
		"blog.example.com {\n\treverse_proxy blog-gate:80\n}\n")

	out, err := b.run(t, "")
	if err != nil {
		t.Fatalf("a gateless box with no on-demand route was refused: %v\n%s", err, out)
	}
	got := b.caddyfile(t)
	if !strings.Contains(got, "import /etc/caddy/routes/*.caddy") {
		t.Errorf("no Caddyfile was written:\n%s", got)
	}
	if strings.Contains(got, "on_demand_tls") {
		t.Errorf("a gate appeared out of nowhere:\n%s", got)
	}
}

// And with the flag, the gate is emitted -- byte for byte, because a block
// Caddy cannot parse is the same outage the refusal exists to prevent.
func TestTheGateIsEmittedVerbatim(t *testing.T) {
	b := newProxyBox(t)

	out, err := b.run(t, "https://gate.example.com/ask")
	if err != nil {
		t.Fatalf("a run with a gate failed: %v\n%s", err, out)
	}
	want := "{\n" +
		"\t# Certificates for wildcard hostnames are issued on demand, one per\n" +
		"\t# name. Without a gate, anyone who pointed a DNS record at this box\n" +
		"\t# could make it request certificates on their behalf -- so an app is\n" +
		"\t# asked whether a hostname is real. Set with: komizo proxy --tls-ask\n" +
		"\ton_demand_tls {\n" +
		"\t\task https://gate.example.com/ask\n" +
		"\t}\n" +
		"}\n"
	if got := b.caddyfile(t); !strings.Contains(got, want) {
		t.Errorf("the emitted gate block is not the one the script documents.\nwant:\n%s\ngot:\n%s", want, got)
	}
}

// A gated re-run on a box with on-demand routes is the normal case and must
// not be refused by the guard: the gate and the route coexist by design.
func TestAnOnDemandRouteWithAGateIsWritten(t *testing.T) {
	b := newProxyBox(t)
	write(t, filepath.Join(b.routes, "blog.caddy"), 0o644,
		"*.blog.example.com {\n\ttls {\n\t\ton_demand\n\t}\n\treverse_proxy blog-gate:80\n}\n")

	out, err := b.run(t, "https://gate.example.com/ask")
	if err != nil {
		t.Fatalf("a gated re-run over an on-demand route was refused: %v\n%s", err, out)
	}
	if got := b.caddyfile(t); !strings.Contains(got, "ask https://gate.example.com/ask") {
		t.Errorf("the gate did not reach the Caddyfile:\n%s", got)
	}
}
