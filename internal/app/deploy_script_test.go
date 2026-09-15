package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/scripts"
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
	root, appDir, routes, proxyDir, state, bin, config string
	script                                             string
	// env is extra environment for the docker stub, so a test can choose which
	// docker call fails.
	env []string
}

func newDeployBox(t *testing.T) *deployBox {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	root := t.TempDir()
	b := &deployBox{
		root:     root,
		appDir:   filepath.Join(root, "srv", "blog"),
		routes:   filepath.Join(root, "srv", "_proxy", "routes"),
		proxyDir: filepath.Join(root, "srv", "_proxy"),
		state:    filepath.Join(root, "state"),
		bin:      filepath.Join(root, "bin"),
		config:   filepath.Join(root, "config"),
	}
	for _, d := range []string{b.appDir, b.routes, b.state, b.bin, b.config} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// A proxy Caddyfile WITH an on-demand gate, so a box that supports wildcards
	// is the default here. deploy-<app> refuses a wildcard when no gate exists
	// (that path is covered by TestAWildcardWithoutATLSGateIsRefused); use
	// b.ungateProxy() to model a box that has not configured one.
	write(t, filepath.Join(b.proxyDir, "Caddyfile"), 0o644,
		"{\n\ton_demand_tls {\n\t\task https://localhost/ask\n\t}\n}\nimport /etc/caddy/routes/*.caddy\n")

	// A docker that answers the handful of things the script asks it, and
	// copies the "config image" out of a directory instead of a registry.
	write(t, filepath.Join(b.bin, "docker"), 0o755, `#!/bin/sh
case "$1" in
  cp)  cp -a "$STUB_CONFIG/." "$3"; exit 0 ;;
  create) echo stubcid; exit 0 ;;
  ps)  echo komizo-proxy; exit 0 ;;
  compose)
    # A pull that fails is the interesting one: it happens AFTER the route
    # file has been written and validated, so it is the only failure that can
    # leave a published route behind.
    for a in "$@"; do
      if [ "$a" = "pull" ] && [ -n "$STUB_PULL_FAILS" ]; then
        echo "Error response from daemon: manifest unknown" >&2
        exit 1
      fi
    done
    exit 0 ;;
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
		"__PROXY_DIR__", b.proxyDir,
		"__ROUTES_DIR__", b.routes,
		"__STATE_DIR__", b.state,
	).Replace(body)
	if strings.Contains(b.script, "__APP") || strings.Contains(b.script, "__PROXY") ||
		strings.Contains(b.script, "__CONFIG") || strings.Contains(b.script, "__ROUTES") ||
		strings.Contains(b.script, "__STATE") {
		t.Fatal("the deploy template has a placeholder this test does not substitute")
	}
	return b
}

// ungateProxy models a box whose proxy has no on-demand-TLS gate configured --
// the state a fresh `komizo proxy` (no --tls-ask) leaves behind.
func (b *deployBox) ungateProxy(t *testing.T) {
	t.Helper()
	write(t, filepath.Join(b.proxyDir, "Caddyfile"), 0o644,
		"import /etc/caddy/routes/*.caddy\n")
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
	cmd.Env = append(append(os.Environ(),
		"STUB_CONFIG="+b.config,
		"PATH="+b.bin+":/usr/bin:/bin",
	), b.env...)
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

func (b *deployBox) dotenv(t *testing.T) string {
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
		"blog.example.com", "www.blog.example.com", "reverse_proxy blog-gate:80",
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
	if got := b.dotenv(t); !strings.Contains(got, "APP_VERSION=abc123") {
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
	if got := b.dotenv(t); !strings.Contains(got, "APP_VERSION=abc123") {
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
	if got := b.dotenv(t); !strings.Contains(got, "APP_VERSION=abc123") {
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

// A wildcard needs on-demand TLS, and on-demand TLS with no approval gate lets
// anyone exhaust the box's shared ACME rate limit with random SNIs. So a
// wildcard is refused unless the proxy has a gate configured, and refused before
// anything is written.
func TestAWildcardWithoutATLSGateIsRefused(t *testing.T) {
	b := newDeployBox(t)
	b.ungateProxy(t)
	b.publishes(t, "services:\n  web:\n    image: x\n",
		"*.preview.blog.example.com -> web\n")

	out, err := b.deploy(t, "abc123")
	if err == nil {
		t.Fatalf("a wildcard was accepted with no on-demand gate:\n%s", out)
	}
	if !strings.Contains(out, "tls-ask") {
		t.Errorf("the refusal should point at 'komizo proxy --tls-ask':\n%s", out)
	}
	if r := b.route(t); r != "" {
		t.Errorf("a route was written despite the refusal:\n%s", r)
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

// A deploy that dies at `docker compose pull` must leave nothing published.
//
// This is the gap the audit called H3. The .prev backups used to be deleted
// just BEFORE the pull, on the reasoning that everything above it had been
// validated -- but the pull is the first step that can fail for a reason
// nothing above it can see: a tag that exists for the config image and not for
// an app image. When it did, .env was restored and the new compose.yml and the
// new ROUTE FILE were not, because their backups were already gone.
//
// The route is the half that matters. It is syntactically valid and it sits in
// the directory the shared proxy imports, so although THIS deploy does not
// reload Caddy, the next deploy of any other app on the box does -- and at that
// moment the hostnames of a stack that never started begin resolving to a gate
// that is not there. A green "nothing restarted" and a domain that 502s, with
// nothing connecting the two.
func TestAFailedPullLeavesNothingPublished(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services:\n  web:\n    image: good\n", "blog.example.com\n")
	if out, err := b.deploy(t, "abc123"); err != nil {
		t.Fatalf("first deploy failed: %v\n%s", err, out)
	}
	routeBefore, composeBefore := b.route(t), b.read(t, filepath.Join(b.appDir, "compose.yml"))
	if routeBefore == "" {
		t.Fatal("the first deploy published no route, so this proves nothing")
	}

	// A second version that is fine in every way this script can check, and
	// whose images do not exist.
	b.env = []string{"STUB_PULL_FAILS=1"}
	b.publishes(t, "services:\n  web:\n    image: missing\n",
		"blog.example.com\nnew.example.com\n")
	out, err := b.deploy(t, "def456")
	if err == nil {
		t.Fatalf("a failed pull should fail the deploy:\n%s", out)
	}

	// The route is the one this test exists for.
	if got := b.route(t); got != routeBefore {
		t.Errorf("the route was left at the version that never started.\nbefore:\n%s\nafter:\n%s",
			routeBefore, got)
	}
	if strings.Contains(b.route(t), "new.example.com") {
		t.Error("a hostname from the failed version is published; the next app's " +
			"deploy would reload Caddy and start serving it")
	}
	if got := b.read(t, filepath.Join(b.appDir, "compose.yml")); got != composeBefore {
		t.Errorf("compose.yml was left at the failed version:\n%s", got)
	}
	if got := b.read(t, filepath.Join(b.appDir, "hostnames")); strings.Contains(got, "new.example.com") {
		t.Errorf("the hostnames record claims names that were never served:\n%s", got)
	}
	// .env was already restored before this fix; assert it still is, so the
	// wider revert cannot regress the narrower one.
	if got := b.dotenv(t); !strings.Contains(got, "APP_VERSION=abc123") {
		t.Errorf("the box no longer claims the version it is actually running: %q", got)
	}
	// And the backups go, so the next deploy's revert restores this state and
	// not something older.
	for _, leftover := range []string{"compose.yml.prev", "hostnames.prev"} {
		if _, err := os.Stat(filepath.Join(b.appDir, leftover)); err == nil {
			t.Errorf("%s was left behind", leftover)
		}
	}
	if _, err := os.Stat(filepath.Join(b.routes, "blog.caddy.prev")); err == nil {
		t.Error("blog.caddy.prev was left behind")
	}
}

// The claim on a hostname is taken under a box-wide lock, so the scan of other
// apps and the write that publishes this app's names cannot interleave.
//
// The deploy lock is deliberately per-app -- two different apps should deploy
// at once -- which is exactly why this needs its own. Without it both apps pass
// the duplicate check, both write routes, and whichever validates second fails
// with "the routes generated from X do not load"; on the other interleaving the
// FIRST app fails for a conflict the second one caused.
//
// Asserted through the lock's own effects rather than by racing two shells,
// which would be a test that passes for timing reasons.
func TestTheHostnameClaimIsTakenUnderALock(t *testing.T) {
	b := newDeployBox(t)
	b.publishes(t, "services:\n  web:\n    image: x\n", "blog.example.com\n")
	if out, err := b.deploy(t, "abc123"); err != nil {
		t.Fatalf("deploy failed: %v\n%s", err, out)
	}

	// The lock spans the scan and the claim, and nothing else: it is released
	// before the route is written, so a slow Caddy validate cannot hold up
	// another app's claim.
	i := strings.Index(b.script, `claim_lock="`)
	j := strings.Index(b.script, "> hostnames")
	if i < 0 || j < 0 || j < i {
		t.Fatal("the claim section is not where this test expects it -- markers moved")
	}
	claim := b.script[i:j]
	if !strings.Contains(claim, "flock") {
		t.Error("the hostname claim is not taken under a lock")
	}
	if !strings.Contains(claim, "is already claimed by") {
		t.Error("the duplicate scan is outside the lock, so the check and the " +
			"claim are not atomic")
	}
	// Released explicitly rather than left to process exit, so the section is
	// bounded by something a reader can see.
	after := b.script[j:]
	if !strings.Contains(after[:120], "exec 8>&-") {
		t.Error("the lock is not released once the claim is written")
	}

	// A second deploy must not block on a lock the first failed to drop.
	done := make(chan error, 1)
	go func() { _, err := b.deploy(t, "def456"); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the second deploy failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the second deploy blocked -- the first did not release the lock")
	}
}
