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
		"/etc/komizo/workloads", filepath.Join(root, "workloads"),
	).Replace(scripts.AlpineProxyScript)
	return b
}

func TestProxyRecreationRetainsProtectedPrivateIngress(t *testing.T) {
	b := newProxyBox(t)
	policyDir := filepath.Join(b.root, "workloads")
	if err := os.Mkdir(policyDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"alpha", "beta"} {
		write(t, filepath.Join(policyDir, app+".json"), 0600, "{}")
	}
	write(t, filepath.Join(b.bin, "komizo-box"), 0755, "#!/bin/sh\napp=$(basename \"$4\" .json)\nprintf 'komizo-%s-ingress\\n' \"$app\"\n")
	write(t, filepath.Join(b.bin, "docker"), 0755, `#!/bin/sh
if [ "$1 $2" = 'network inspect' ] && [ "$4" = '--format' ]; then
 case "$3" in
  komizo-alpha-ingress) echo 'true|alpha' ;;
  komizo-beta-ingress) echo 'true|beta' ;;
  *) exit 1 ;;
 esac
fi
`)
	if out, err := b.run(t, ""); err != nil {
		t.Fatalf("proxy failed: %v\n%s", err, out)
	}
	body, err := os.ReadFile(filepath.Join(b.proxyDir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"komizo-alpha-ingress", "komizo-beta-ingress"} {
		if !strings.Contains(string(body), "      - "+name+"\n") || !strings.Contains(string(body), "  "+name+":\n    external: true\n    name: "+name+"\n") {
			t.Fatalf("proxy lost protected ingress %s:\n%s", name, body)
		}
	}
}

func TestProxyRefusesForeignPrivateIngressBeforeChangingConfiguration(t *testing.T) {
	b := newProxyBox(t)
	policyDir := filepath.Join(b.root, "workloads")
	if err := os.Mkdir(policyDir, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(policyDir, "alpha.json"), 0600, "{}")
	write(t, filepath.Join(b.bin, "komizo-box"), 0755, "#!/bin/sh\necho komizo-alpha-ingress\n")
	write(t, filepath.Join(b.bin, "docker"), 0755, "#!/bin/sh\nif [ \"$1 $2\" = 'network inspect' ] && [ \"$4\" = '--format' ]; then echo 'true|other'; fi\n")
	write(t, filepath.Join(b.proxyDir, "Caddyfile"), 0644, "original")
	if out, err := b.run(t, ""); err == nil || !strings.Contains(out, "protected owner") {
		t.Fatalf("foreign ingress accepted: %v\n%s", err, out)
	}
	if got := b.caddyfile(t); got != "original" {
		t.Fatalf("configuration changed: %s", got)
	}
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

func (b *proxyBox) tlsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(b.root, "tls")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "Caddyfile"), 0o600, "*.preview.example.com {\n tls internal\n respond 404\n}\n")
	// Fake root ownership like the existing id/chown stubs; actual file modes
	// still come from the filesystem, so unsafe permissions are exercised.
	write(t, filepath.Join(b.bin, "docker"), 0o755, "#!/bin/sh\ncase \"$*\" in *version) echo v2.10.2;; esac\nexit 0\n")
	write(t, filepath.Join(b.bin, "stat"), 0o755, "#!/bin/sh\nif [ \"$2\" = '%u' ]; then echo 0; else exec /usr/bin/stat \"$@\"; fi\n")
	return dir
}

func (b *proxyBox) runTLS(t *testing.T, dir string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(b.script)
	cmd.Env = append(os.Environ(), "PATH="+b.bin+":/usr/bin:/bin", "TLS_ASK=", "TLS_CONFIG_DIR="+dir, "API_SOCKET_DIR="+filepath.Join(b.root, "run", "komizo", "api"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestWildcardTLSUsesNarrowReadOnlyMountAndPersistentCertificates(t *testing.T) {
	b := newProxyBox(t)
	dir := b.tlsDir(t)
	image := "ghcr.io/example/caddy-dns@sha256:" + strings.Repeat("a", 64)
	t.Setenv("PROXY_IMAGE", image)
	write(t, filepath.Join(dir, "secrets.env"), 0o600, "DNS_TOKEN=test-only\n")
	if out, err := b.runTLS(t, dir); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(b.caddyfile(t), "import /etc/caddy/tls/Caddyfile") {
		t.Fatal("missing TLS policy import")
	}
	data, err := os.ReadFile(filepath.Join(b.proxyDir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"image: " + image, dir + ":/etc/caddy/tls:ro", dir + "/secrets.env", "caddy_data:/data", "caddy_config:/config"} {
		if !strings.Contains(string(data), required) {
			t.Errorf("missing %s", required)
		}
	}
	if strings.Contains(string(data), "DNS_TOKEN") {
		t.Fatal("credential copied into generated compose")
	}
	old := b.caddyfile(t)
	if out, err := b.runTLS(t, ""); err == nil || !strings.Contains(out, "--tls-config-dir") {
		t.Fatalf("coverage silently removed: %v %s", err, out)
	}
	if b.caddyfile(t) != old {
		t.Fatal("refused rerun changed Caddyfile")
	}
}

func TestWildcardTLSValidationFailureLeavesRunningConfigurationUntouched(t *testing.T) {
	b := newProxyBox(t)
	dir := b.tlsDir(t)
	write(t, filepath.Join(b.proxyDir, "Caddyfile"), 0o644, "original config\n")
	write(t, filepath.Join(b.proxyDir, "compose.yml"), 0o644, "original compose\n")
	write(t, filepath.Join(b.bin, "docker"), 0o755, "#!/bin/sh\ncase \"$*\" in *version) echo v2.10.2; exit 0;; esac\nif [ \"$1\" = run ]; then echo DO_NOT_LEAK_CREDENTIAL >&2; exit 1; fi\necho unexpected docker mutation >&2\nexit 99\n")
	out, err := b.runTLS(t, dir)
	if err == nil || !strings.Contains(out, "running proxy was not changed") {
		t.Fatalf("%v: %s", err, out)
	}
	if strings.Contains(out, "DO_NOT_LEAK") || strings.Contains(out, "unexpected docker") {
		t.Fatalf("unsafe failure: %s", out)
	}
	if b.caddyfile(t) != "original config\n" {
		t.Fatal("Caddyfile overwritten before validation")
	}
	data, _ := os.ReadFile(filepath.Join(b.proxyDir, "compose.yml"))
	if string(data) != "original compose\n" {
		t.Fatal("compose overwritten before validation")
	}
}

func TestWildcardTLSRejectsAppWritableConfiguration(t *testing.T) {
	b := newProxyBox(t)
	dir := b.tlsDir(t)
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if out, err := b.runTLS(t, dir); err == nil || !strings.Contains(out, "must not be writable") {
		t.Fatalf("%v: %s", err, out)
	}
	if b.caddyfile(t) != "" {
		t.Fatal("unsafe configuration was installed")
	}
}

func TestTLSConfigDirectoryValidation(t *testing.T) {
	for _, path := range []string{"", "/etc/komizo/tls", "/srv/_proxy/tls"} {
		if err := validateTLSConfigDir(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	for _, path := range []string{"/", "relative", "/etc//tls", "/etc/../tls", "/etc/..", "/etc/tls/", "/etc/tls\nsite", "/etc/$(id)"} {
		if validateTLSConfigDir(path) == nil {
			t.Errorf("accepted %q", path)
		}
	}
}

func TestWildcardTLSRejectsCaddyWithoutWildcardReuse(t *testing.T) {
	b := newProxyBox(t)
	dir := b.tlsDir(t)
	write(t, filepath.Join(b.bin, "docker"), 0o755, "#!/bin/sh\necho v2.9.1\nexit 0\n")
	out, err := b.runTLS(t, dir)
	if err == nil || !strings.Contains(out, "Caddy 2.10 or newer") {
		t.Fatalf("%v: %s", err, out)
	}
	if b.caddyfile(t) != "" {
		t.Fatal("old Caddy configuration was installed")
	}
}
