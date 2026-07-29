package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo-be/cli/scripts"
)

// deploy-<app> is the only thing on the box a leaked CI key can invoke, it runs
// as root, and it is the largest piece of generated code komizo ships. Parsing
// it proves nothing about what it does, so this runs it.
//
// Docker is stubbed. Nothing here tests Docker; what is being tested is the
// part komizo wrote -- which route file is produced, which hostnames are
// recorded, when a deploy is refused, and whether a refusal leaves the box on
// the config it was serving before.

// deployBox is a fake server: an app directory, a routes directory, komizo's
// state files, and a PATH where docker does as it is told.
type deployBox struct {
	root, appDir, routes, state, bin, config string
	script                                   string
}

func newDeployBox(t *testing.T) *deployBox {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	root := t.TempDir()
	b := &deployBox{
		root:   root,
		appDir: filepath.Join(root, "srv", "blog"),
		routes: filepath.Join(root, "srv", "_proxy", "routes"),
		state:  filepath.Join(root, "state"),
		bin:    filepath.Join(root, "bin"),
		config: filepath.Join(root, "config"),
	}
	for _, d := range []string{b.appDir, b.routes, b.state, b.bin, b.config} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// A docker that answers the handful of things the script asks it, and
	// copies the "config image" out of a directory instead of a registry.
	write(t, filepath.Join(b.bin, "docker"), 0o755, `#!/bin/sh
case "$1" in
  cp)  cp -a "$STUB_CONFIG/." "$3"; exit 0 ;;
  create) echo stubcid; exit 0 ;;
  ps)  echo komizo-proxy; exit 0 ;;
esac
exit 0
`)
	// The test does not run as root, and the script chowns what it writes.
	write(t, filepath.Join(b.bin, "chown"), 0o755, "#!/bin/sh\nexit 0\n")

	write(t, filepath.Join(b.appDir, "compose.yml"), 0o644, "services: {}\n")
	write(t, filepath.Join(b.appDir, ".env"), 0o600, "")
	b.setState("blog", b.appDir)

	// The template, substituted exactly as alpine.sh substitutes it -- but
	// pointed at this fake box rather than at /srv and /var/lib.
	body := between(t, scripts.AlpineScript,
		`cat > "$DEPLOY_BIN.tmp" <<'KOMIZO_DEPLOY_EOF'`, "KOMIZO_DEPLOY_EOF")
	b.script = strings.NewReplacer(
		"__APP_NAME__", "blog",
		"__APP_DIR__", b.appDir,
		"__CONFIG_IMAGE__", "ghcr.io/you/blog-config",
		"__PROXY_CONTAINER__", "komizo-proxy",
		"__ROUTES_DIR__", b.routes,
		"__STATE_DIR__", b.state,
	).Replace(body)
	if strings.Contains(b.script, "__") &&
		strings.Contains(b.script, "__APP") {
		t.Fatal("the deploy template has a placeholder this test does not substitute")
	}
	return b
}

func (b *deployBox) setState(app, dir string) {
	_ = os.WriteFile(filepath.Join(b.state, app+".env"),
		[]byte("APP_NAME="+app+"\nAPP_DIR="+dir+"\n"), 0o644)
}

// publishes is what the config image for the next deploy contains.
func (b *deployBox) publishes(t *testing.T, compose, hostnames string) {
	t.Helper()
	write(t, filepath.Join(b.config, "compose.yml"), 0o644, compose)
	p := filepath.Join(b.config, "hostnames")
	if hostnames == "" {
		_ = os.Remove(p)
		return
	}
	write(t, p, 0o644, hostnames)
}

func (b *deployBox) deploy(t *testing.T, version string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-s", version)
	cmd.Stdin = strings.NewReader(b.script)
	cmd.Env = append(os.Environ(),
		"STUB_CONFIG="+b.config,
		"PATH="+b.bin+":/usr/bin:/bin",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (b *deployBox) read(t *testing.T, path string) string {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(got)
}

func (b *deployBox) route(t *testing.T) string {
	return b.read(t, filepath.Join(b.routes, "blog.caddy"))
}

func (b *deployBox) env(t *testing.T) string {
	return b.read(t, filepath.Join(b.appDir, ".env"))
}

func write(t *testing.T, path string, mode os.FileMode, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestADeployWritesTheRouteBesideTheProxyAndNotBesideTheApp(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services:\n  web:\n    image: x\n",
		"blog.example.com -> web\nwww.blog.example.com\n")

	out, err := b.deploy(t, "abc123")
	if err != nil {
		t.Fatalf("deploy failed: %v\n%s", err, out)
	}

	route := b.route(t)
	if route == "" {
		t.Fatalf("no route written to the proxy's directory\n%s", out)
	}
	for _, want := range []string{
		"blog.example.com", "www.blog.example.com", "reverse_proxy blog-gateway:80",
	} {
		if !strings.Contains(route, want) {
			t.Errorf("route is missing %q:\n%s", want, route)
		}
	}
	// The app's own directory holds no server config at all any more. That is
	// what lets the proxy mount only the routes and stop seeing secrets.env.
	if _, err := os.Stat(filepath.Join(b.appDir, "caddy")); err == nil {
		t.Error("the deploy still writes server config into the app's directory")
	}
	// The annotation is recorded -- it is the only thing on the box that knows
	// which container serves a name -- but never reaches the route.
	if hn := b.read(t, filepath.Join(b.appDir, "hostnames")); !strings.Contains(hn, "-> web") {
		t.Errorf("the arrow was not recorded: %q", hn)
	}
	if strings.Contains(route, "-> web") {
		t.Errorf("the arrow leaked into the generated route:\n%s", route)
	}
	if got := b.env(t); !strings.Contains(got, "APP_VERSION=abc123") {
		t.Errorf("version not committed: %q", got)
	}
}

// The check that stops two apps claiming one hostname compared WHOLE LINES
// against a file that stores annotations, so any name another app had declared
// with an arrow matched nothing and the duplicate shipped -- to fail later as
// an unexplained "the routes do not load", or to have Caddy round-robin between
// two apps.
func TestAHostnameAnotherAppAnnotatedStillCollides(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services:\n  web:\n    image: x\n", "blog.example.com\n")
	if out, err := b.deploy(t, "abc123"); err != nil {
		t.Fatalf("first deploy failed: %v\n%s", err, out)
	}

	// Another app claims the same name, and records it WITH an arrow.
	shop := filepath.Join(b.root, "srv", "shop")
	if err := os.MkdirAll(shop, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(shop, "hostnames"), 0o644, "blog.example.com -> other\n")
	b.setState("shop", shop)

	out, err := b.deploy(t, "def456")
	if err == nil {
		t.Fatalf("the deploy should have been refused:\n%s", out)
	}
	if !strings.Contains(out, "already claimed by shop") {
		t.Errorf("expected the collision to name the other app:\n%s", out)
	}
}

// A refused deploy must leave the box exactly as it was serving, or a bad
// config takes down an app that was working.
func TestARefusedDeployLeavesTheBoxOnItsPreviousConfig(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services:\n  web:\n    image: good\n", "blog.example.com\n")
	if out, err := b.deploy(t, "abc123"); err != nil {
		t.Fatalf("first deploy failed: %v\n%s", err, out)
	}
	before := b.route(t)

	// A hostname Caddy would never accept.
	b.publishes(t, "services:\n  web:\n    image: bad\n", "not a hostname!\n")
	out, err := b.deploy(t, "def456")
	if err == nil {
		t.Fatalf("an invalid hostname should have been refused:\n%s", out)
	}

	if got := b.route(t); got != before {
		t.Errorf("the route changed despite the deploy failing:\nbefore:\n%s\nafter:\n%s", before, got)
	}
	if got := b.env(t); !strings.Contains(got, "APP_VERSION=abc123") {
		t.Errorf("the box no longer claims the version it is running: %q", got)
	}
	if got := b.read(t, filepath.Join(b.appDir, "compose.yml")); !strings.Contains(got, "good") {
		t.Errorf("compose.yml was not reverted: %q", got)
	}
	// Backups are cleaned up either way; one left behind is what the NEXT
	// revert would restore.
	for _, leftover := range []string{
		filepath.Join(b.appDir, "compose.yml.prev"),
		filepath.Join(b.appDir, "hostnames.prev"),
		filepath.Join(b.routes, "blog.caddy.prev"),
	} {
		if _, err := os.Stat(leftover); err == nil {
			t.Errorf("%s was left behind", filepath.Base(leftover))
		}
	}
}

func TestAnAppThatPublishesNoHostnamesGetsNoRoute(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services:\n  worker:\n    image: x\n", "")

	out, err := b.deploy(t, "abc123")
	if err != nil {
		t.Fatalf("a worker with no hostnames should deploy: %v\n%s", err, out)
	}
	if got := b.route(t); got != "" {
		t.Errorf("a worker should publish no route, got:\n%s", got)
	}
	if got := b.env(t); !strings.Contains(got, "APP_VERSION=abc123") {
		t.Errorf("version not committed: %q", got)
	}
}

func TestTheDeployRefusesAVersionItCannotSafelyUse(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services: {}\n", "")
	for _, bad := range []string{"", "a b", "a;rm -rf /", "../etc", "a\nb"} {
		if out, err := b.deploy(t, bad); err == nil {
			t.Errorf("version %q was accepted:\n%s", bad, out)
		}
	}
}

// A hostname may say how its certificate is obtained. The mode is optional and
// last, so every file written before it existed is still valid -- which is all
// of them.
func TestAHostnameMaySayHowItsCertificateIsObtained(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services:\n  web:\n    image: x\n",
		"blog.example.com -> web\n*.preview.blog.example.com -> web on-demand\nother.example.com on-demand\n")

	out, err := b.deploy(t, "abc123")
	if err != nil {
		t.Fatalf("deploy failed: %v\n%s", err, out)
	}
	route := b.route(t)
	// on-demand is what a wildcard already got, so saying it changes nothing.
	if !strings.Contains(route, "on_demand") {
		t.Errorf("the wildcard lost its on-demand issuance:\n%s", route)
	}
	// And the mode is no more part of the route than the arrow is.
	for _, leaked := range []string{"on-demand", "-> web"} {
		if strings.Contains(route, leaked) {
			t.Errorf("%q leaked into the generated route:\n%s", leaked, route)
		}
	}
}

// Modes komizo accepts in a file but cannot yet serve are REFUSED, not ignored.
// Falling back to on-demand would hand a name the certificate strategy it asked
// not to have, and the reason to ask is usually that the other one is wrong for
// it -- a DNS-01 wildcard exists precisely to avoid per-name issuance.
func TestAModeKomizoCannotServeIsRefusedRatherThanIgnored(t *testing.T) {
	for _, mode := range []string{"dns", "passthrough"} {
		b := newDeployBox(t)
		b.publishes(t, "services:\n  web:\n    image: x\n",
			"blog.example.com -> web\n*.preview.blog.example.com -> web "+mode+"\n")

		out, err := b.deploy(t, "abc123")
		if err == nil {
			t.Fatalf("%s was accepted:\n%s", mode, out)
		}
		if !strings.Contains(out, mode) || !strings.Contains(out, "tls-design") {
			t.Errorf("%s: the refusal should name the mode and where the decision is written down:\n%s", mode, out)
		}
		// Refused before anything was written, like every other refusal here.
		if r := b.route(t); r != "" {
			t.Errorf("%s: a route was written despite the refusal:\n%s", mode, r)
		}
	}
}

// Anything else after the name is still a syntax error. The mode column widens
// what a line may say; it does not make the file free-form.
func TestSomethingThatIsNeitherAnArrowNorAModeIsStillRefused(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services:\n  web:\n    image: x\n",
		"blog.example.com -> web nonsense\n")
	if out, err := b.deploy(t, "abc123"); err == nil {
		t.Fatalf("junk after the arrow was accepted:\n%s", out)
	}
}
