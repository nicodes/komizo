package main

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func testModel() model {
	m := newModel(target{user: "root", host: "box.example.com", port: 22})
	m.width, m.height = 100, 40
	m.scr = screenList
	m.apps = []appRow{
		{name: "blog", user: "cd-blog", dir: "/srv/blog", version: "a1b2c3d4e5f6a7b8", running: "3", image: "ghcr.io/you/blog-config", routes: "blog.example.com"},
		{name: "shop", user: "cd-shop", dir: "/srv/shop", version: "none", running: "0", image: "ghcr.io/you/shop-config"},
	}
	m.proxy = proxyRow{installed: true, state: "running", network: "edge",
		image: "caddy:2", status: "Up 3 hours"}
	m.srv = serverRow{state: "ready", docker: "Docker version 26.1.3"}
	return m
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func send(m model, keys ...string) model {
	for _, k := range keys {
		next, _ := m.Update(key(k))
		m = next.(model)
	}
	return m
}

func TestListShowsEveryApp(t *testing.T) {
	v := testModel().View()
	for _, want := range []string{"blog", "cd-blog", "blog.example.com", "shop"} {
		if !strings.Contains(v, want) {
			t.Errorf("list view is missing %q", want)
		}
	}
	// The directory and the config image are deliberately not in the list --
	// both are derivable or rarely needed, and the hostname an app serves is
	// what you actually scan this table for. They belong on the detail screen.
	if strings.Contains(v, "/srv/blog") {
		t.Error("the list should stay compact; the directory belongs in the detail view")
	}
	if strings.Contains(v, "ghcr.io/you/blog-config") {
		t.Error("the config image belongs in the detail view, not the list")
	}
	// A long SHA is trimmed, but to something that still identifies the commit.
	if !strings.Contains(v, "a1b2c3d4e5f6") {
		t.Error("list view should show a shortened version")
	}
	if strings.Contains(v, "a1b2c3d4e5f6a7b8") {
		t.Error("list view should not show the full 16-char version")
	}
}

func TestEmptyListExplainsWhatAnAppIs(t *testing.T) {
	m := testModel()
	m.apps = nil
	v := m.View()
	if !strings.Contains(v, "No apps") {
		t.Error("empty list should say so")
	}
	if !strings.Contains(v, "add") {
		t.Error("empty list should point at adding one")
	}
}

func TestCursorStaysInRange(t *testing.T) {
	m := send(testModel(), "up", "up", "up")
	if m.cursor != 0 {
		t.Errorf("cursor went above the first row: %d", m.cursor)
	}
	m = send(m, "down", "down", "down", "down")
	if m.cursor != len(m.apps)-1 {
		t.Errorf("cursor went past the last row: %d", m.cursor)
	}
}

func TestDetailShowsTheSelectedApp(t *testing.T) {
	m := send(testModel(), "down", "enter")
	if m.scr != screenDetail {
		t.Fatalf("enter did not open the detail screen, got %v", m.scr)
	}
	v := m.View()
	for _, want := range []string{"shop", "/srv/shop", "cd-shop", "deploy-shop", "set-secret-shop", "ghcr.io/you/shop-config"} {
		if !strings.Contains(v, want) {
			t.Errorf("detail view is missing %q", want)
		}
	}
	m = send(m, "esc")
	if m.scr != screenList {
		t.Error("esc should return to the list")
	}
}

func TestAddFormValidatesBeforeRunning(t *testing.T) {
	m := send(testModel(), "a")
	if m.scr != screenAddForm {
		t.Fatalf("'a' did not open the add form, got %v", m.scr)
	}
	// A tag in the config image is the mistake most worth catching, since the
	// deploy supplies the tag.
	m = send(m, "b", "l", "o", "g", "tab")
	for _, r := range "ghcr.io/you/blog-config:v1" {
		m = send(m, string(r))
	}
	m = send(m, "enter")
	if m.scr != screenAddForm {
		t.Error("form should stay open when a field is invalid")
	}
	if !strings.Contains(m.form.problem, "tag") {
		t.Errorf("expected a complaint about the tag, got %q", m.form.problem)
	}
}

func TestAddFormRejectsABadAppName(t *testing.T) {
	m := send(testModel(), "a")
	for _, r := range "bad name" {
		m = send(m, string(r))
	}
	m = send(m, "tab")
	for _, r := range "ghcr.io/you/x-config" {
		m = send(m, string(r))
	}
	m = send(m, "enter")
	if m.scr != screenAddForm || m.form.problem == "" {
		t.Error("a space in the app name should be rejected")
	}
}

func TestRemoveRequiresTypingTheAppName(t *testing.T) {
	m := send(testModel(), "x")
	if m.scr != screenConfirm {
		t.Fatalf("'x' did not open a confirmation, got %v", m.scr)
	}
	v := m.View()
	for _, want := range []string{"/srv/blog", "cd-blog", "cannot be undone"} {
		if !strings.Contains(v, want) {
			t.Errorf("the confirmation should spell out %q", want)
		}
	}
	// Enter alone must not be enough.
	m = send(m, "enter")
	if m.scr != screenConfirm {
		t.Error("enter without typing the name should not start the removal")
	}
	m = send(m, "b", "l", "o")
	m = send(m, "enter")
	if m.scr != screenConfirm {
		t.Error("a partial name should not start the removal")
	}
}

func TestRotateDoesNotRequireTyping(t *testing.T) {
	m := send(testModel(), "r")
	if m.scr != screenConfirm {
		t.Fatalf("'r' did not open a confirmation, got %v", m.scr)
	}
	if m.confirm.confirmWord != "" {
		t.Error("rotating a key does not delete data; it should not demand typing")
	}
	if !strings.Contains(m.View(), "stops working") {
		t.Error("the rotate confirmation should warn that the old key dies immediately")
	}
}

func TestEscLeavesEveryScreen(t *testing.T) {
	for _, open := range []string{"a", "x", "r"} {
		m := send(testModel(), open, "esc")
		if m.scr != screenList {
			t.Errorf("esc from %q did not return to the list, got %v", open, m.scr)
		}
	}
}

func TestResultShowsBothValuesToPaste(t *testing.T) {
	r := addResult{
		app:        "blog",
		keyPath:    "/home/you/.ssh/deploy_blog_box",
		knownHosts: "box ssh-ed25519 AAAA",
	}
	v := r.view()
	for _, want := range []string{"SSH_DEPLOY_KEY", "SSH_KNOWN_HOSTS", "deploy_blog_box", "app: blog"} {
		if !strings.Contains(v, want) {
			t.Errorf("result is missing %q", want)
		}
	}
	// The private key itself must never be rendered.
	if strings.Contains(v, "PRIVATE KEY") {
		t.Error("the result must not print the key material")
	}
}

func TestRotatedResultWarnsAboutTheOldKey(t *testing.T) {
	v := addResult{app: "blog", keyPath: "/k", knownHosts: "h k b", rotated: true}.view()
	if !strings.Contains(v, "stopped working") {
		t.Error("a rotation result should say the old key is already dead")
	}
}

func TestInventoryParsing(t *testing.T) {
	out := strings.Join([]string{
		"server\tready\tDocker version 26.1.3",
		"app\tblog\tcd-blog\t/srv/blog\ta1b2\t2\tghcr.io/you/blog-config\tblog.example.com",
		"app\tworker\tcd-worker\t/srv/worker\tnone\t0\tghcr.io/you/worker-config\t",
		"proxy\trunning\tedge\tcaddy:2\tUp 3 hours",
		"net\tedge\tbridge\t172.18.0.0/16",
		"netmember\tkomizo-caddy\tcaddy,komizo-caddy",
		"netmember\tblog-web-1\tweb,blog-web",
		"orphan\tghost",
		"", // trailing blank, as the server emits
	}, "\n")
	apps, srv, proxy, net, orphans := parseInventory(out)
	if !srv.ready() {
		t.Errorf("server should parse as ready, got %+v", srv)
	}
	if len(apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(apps))
	}
	if apps[0].name != "blog" || apps[0].image != "ghcr.io/you/blog-config" {
		t.Errorf("first app parsed wrong: %+v", apps[0])
	}
	if apps[0].routes != "blog.example.com" {
		t.Errorf("routes not parsed: %q", apps[0].routes)
	}
	// An app with no routes is normal -- a worker or a cron job.
	if apps[1].routes != "" {
		t.Errorf("expected no routes for worker, got %q", apps[1].routes)
	}
	if !proxy.installed || !proxy.running() || proxy.network != "edge" {
		t.Errorf("proxy parsed wrong: %+v", proxy)
	}
	if proxy.image != "caddy:2" || proxy.status != "Up 3 hours" {
		t.Errorf("proxy image/status parsed wrong: %+v", proxy)
	}
	if len(orphans) != 1 || orphans[0] != "ghost" {
		t.Errorf("expected one orphan named ghost, got %v", orphans)
	}
	if net.name != "edge" || net.driver != "bridge" || net.subnet != "172.18.0.0/16" {
		t.Errorf("network parsed wrong: %+v", net)
	}
	if len(net.members) != 2 {
		t.Fatalf("expected 2 attached containers, got %d", len(net.members))
	}
	if got := net.members[1].aliases; len(got) != 2 || got[0] != "web" {
		t.Errorf("aliases parsed wrong: %v", got)
	}
}

func TestInventoryWithoutAProxy(t *testing.T) {
	// A box with no proxy emits no proxy record at all; that must read as
	// "not installed" rather than as an empty-but-present proxy.
	_, _, proxy, _, _ := parseInventory("app\tblog\tcd-blog\t/srv/blog\ta1b2\t2\tghcr.io/you/blog-config\t")
	if proxy.installed {
		t.Errorf("no proxy record should mean not installed, got %+v", proxy)
	}
}

func TestReservedAppNames(t *testing.T) {
	// /srv/_proxy is komizo's own; an app taking that name would collide with it
	// and the inventory could no longer tell them apart.
	for _, bad := range []string{"_proxy", "_", "_anything"} {
		if err := validateApp(bad); err == nil {
			t.Errorf("%q should be rejected as reserved", bad)
		}
	}
	for _, ok := range []string{"blog", "my_app", "a-b", "x_"} {
		if err := validateApp(ok); err != nil {
			t.Errorf("%q should be allowed: %v", ok, err)
		}
	}
}

func TestProxyFormValidates(t *testing.T) {
	// Reached with 's' from the server screen.
	m := send(testModel(), "s", "s")
	if m.scr != screenProxyForm {
		t.Fatalf("'s' did not open the settings form, got %v", m.scr)
	}
	// An empty network would produce a compose file referencing nothing.
	m = send(m, "backspace", "backspace", "backspace", "backspace")
	m = send(m, "enter", "enter")
	if m.scr != screenProxyForm || m.proxyForm.problem == "" {
		t.Error("an empty network name should be rejected")
	}
	// The defaults are filled in, so a user who just hits enter gets a working
	// proxy rather than an empty network name.
	if got := newProxyForm().opts(); got.network != defaultNetwork || got.image != defaultProxy {
		t.Errorf("proxy form defaults are wrong: %+v", got)
	}
}

func TestProxyFormPrefillsFromTheServer(t *testing.T) {
	// Re-running to change one value must not reset the others.
	f := newProxyForm()
	f.set(proxyRow{installed: true, state: "running", network: "web", image: "caddy:2.8"})
	o := f.opts()
	if o.network != "web" || o.image != "caddy:2.8" {
		t.Errorf("form did not prefill from the server: %+v", o)
	}
}

func TestListProxyLineAlwaysSaysSomething(t *testing.T) {
	if !strings.Contains(listProxyLine(proxyRow{}), "no shared proxy") {
		t.Error("a box with no proxy should say so, not show nothing")
	}
	if !strings.Contains(listProxyLine(proxyRow{installed: true, state: "stopped"}), "NOT running") {
		t.Error("a stopped proxy is the loudest possible problem; it must be called out")
	}
	// Both point at the same key, since there is now only one to remember.
	for _, p := range []proxyRow{{}, {installed: true, state: "stopped"}} {
		if !strings.Contains(listProxyLine(p), "press s") {
			t.Errorf("the list should say which key fixes it: %q", listProxyLine(p))
		}
	}
}

func TestKnownHostsFieldBracketsANonDefaultPort(t *testing.T) {
	// CI pins the host key by this exact string, so a server on a non-default
	// port must be written [host]:port or the pin never matches.
	if got := (target{host: "box", port: 22}).knownHostsField(); got != "box" {
		t.Errorf("port 22 should be bare, got %q", got)
	}
	if got := (target{host: "box", port: 2222}).knownHostsField(); got != "[box]:2222" {
		t.Errorf("a non-default port should be bracketed, got %q", got)
	}
}

func TestSSHArgsOnlyForcesAnExplicitPort(t *testing.T) {
	// Passing -p unconditionally would override a Port in the user's ssh config.
	joined := strings.Join((target{user: "root", host: "box", port: 2222}).sshArgs("true"), " ")
	if strings.Contains(joined, "-p") {
		t.Errorf("port was not explicit, so -p should be absent: %s", joined)
	}
	joined = strings.Join((target{user: "root", host: "box", port: 2222, portExplicit: true}).sshArgs("true"), " ")
	if !strings.Contains(joined, "-p 2222") {
		t.Errorf("an explicit port should be passed to ssh: %s", joined)
	}
}

func TestFreshServerGetsTheInitScreen(t *testing.T) {
	// A box with nothing installed must not look like a set-up server that
	// happens to have no apps -- those are different problems with different
	// next steps.
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40
	next, _ := m.Update(appsMsg{srv: serverRow{state: "bare"}})
	m = next.(model)
	if m.scr != screenInit {
		t.Fatalf("a bare server should open the init screen, got %v", m.scr)
	}
	v := m.View()
	for _, want := range []string{"not set up yet", "docker", "caddy", "edge"} {
		if !strings.Contains(strings.ToLower(v), strings.ToLower(want)) {
			t.Errorf("init screen is missing %q", want)
		}
	}
}

func TestReadyServerGoesStraightToTheList(t *testing.T) {
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40
	next, _ := m.Update(appsMsg{srv: serverRow{state: "ready"}})
	if next.(model).scr != screenList {
		t.Error("a ready server should go straight to the app list")
	}
}

func TestChangingTheNetworkIsWarnedAbout(t *testing.T) {
	// Moving the proxy strands every app on the old network, because each names
	// it in its own config image. Silently allowing that would be a trap.
	f := newProxyForm()
	f.set(proxyRow{installed: true, state: "running", network: "edge", image: "caddy:2"})
	f.fields[0].value = "web"
	v := f.view(proxyRow{installed: true, state: "running", network: "edge"})
	if !strings.Contains(v, "strands every app") {
		t.Error("changing the network should warn what it costs")
	}
	// No warning when it is unchanged.
	f2 := newProxyForm()
	f2.set(proxyRow{installed: true, state: "running", network: "edge", image: "caddy:2"})
	if strings.Contains(f2.view(proxyRow{installed: true, network: "edge"}), "strands every app") {
		t.Error("no warning is due when the network is not being changed")
	}
}

func TestNothingAsksForAnAcmeEmail(t *testing.T) {
	// Let's Encrypt stopped sending expiry notices in June 2025, so the address
	// bought nothing but a field to fill in. If one comes back, it should be a
	// deliberate decision rather than a copied form field.
	for _, f := range newProxyForm().fields {
		if strings.Contains(strings.ToLower(f.label), "email") {
			t.Errorf("proxy form still asks for %q", f.label)
		}
	}
}

func TestServerScreenShowsAllThree(t *testing.T) {
	// Docker, the network and the proxy were a key each. They answer one
	// question between them, so they share a page.
	m := send(netModel(), "s")
	if m.scr != screenServer {
		t.Fatalf("'s' should open the server screen, got %v", m.scr)
	}
	v := m.View()
	for _, want := range []string{
		"Server",
		"Docker version 26.1.3", // docker
		"edge", "bridge",        // network
		"running", "caddy:2", // proxy
		"blog-web-1", // what is attached
	} {
		if !strings.Contains(v, want) {
			t.Errorf("server screen is missing %q", want)
		}
	}
}

func TestServerScreenWithNoProxyOffersToInstallOne(t *testing.T) {
	m := netModel()
	m.proxy = proxyRow{}
	m = send(m, "s")
	if m.scr != screenServer {
		t.Fatalf("'s' should still open the server screen, got %v", m.scr)
	}
	v := m.View()
	if !strings.Contains(v, "not installed") {
		t.Error("it should say there is no proxy")
	}
	if !strings.Contains(v, "install a proxy") {
		t.Error("it should offer to install one")
	}
	// And 's' from there reaches the form.
	m = send(m, "s")
	if m.scr != screenProxyForm {
		t.Errorf("'s' should open the settings form, got %v", m.scr)
	}
}

func TestStoppingTheProxyIsConfirmed(t *testing.T) {
	m := send(netModel(), "s", "t")
	if m.scr != screenConfirm {
		t.Fatalf("stopping the proxy should confirm first, got %v", m.scr)
	}
	if !strings.Contains(m.View(), "EVERY app") {
		t.Error("the confirmation must say it takes every app on the box down")
	}
}

func TestStartingTheProxyIsNotConfirmed(t *testing.T) {
	// Starting cannot lose anything, so it should not ask.
	m := netModel()
	m.proxy = proxyRow{installed: true, state: "stopped", network: "edge"}
	m = send(m, "s", "t")
	if m.scr != screenRunning {
		t.Errorf("starting a stopped proxy should just run, got %v", m.scr)
	}
}

func TestStoppedProxyIsShouted(t *testing.T) {
	m := netModel()
	m.proxy = proxyRow{installed: true, state: "stopped", network: "edge", status: "Exited (0) 5 minutes ago"}
	v := send(m, "s").View()
	// Case-insensitive: the wording is a style choice, that it is called out is not.
	if !strings.Contains(strings.ToLower(v), "stopped") {
		t.Error("a stopped proxy should be unmissable")
	}
	if !strings.Contains(v, "unreachable") {
		t.Error("it should spell out that every app is down")
	}
	if !strings.Contains(v, "Exited (0) 5 minutes ago") {
		t.Error("docker's own status is the most useful line here; show it")
	}
	if !strings.Contains(v, "start proxy") {
		t.Error("a stopped proxy should offer to start, not stop")
	}
}

func TestProxyLogsRender(t *testing.T) {
	m := send(netModel(), "s")
	next, _ := m.Update(proxyLogsMsg{lines: "obtaining certificate\nchallenge failed"})
	v := next.(model).View()
	if !strings.Contains(v, "challenge failed") {
		t.Error("proxy logs should render; they are usually the answer to a TLS problem")
	}
}

func TestProxyComposeCommandTargetsTheProject(t *testing.T) {
	// A compose project cannot be named after /srv/_proxy, so the project name
	// is pinned separately. If these drift, start/stop silently act on nothing.
	got := proxyCompose("restart")
	for _, want := range []string{"/srv/_proxy/compose.yml", "-p komizo-proxy", "restart"} {
		if !strings.Contains(got, want) {
			t.Errorf("compose command %q is missing %q", got, want)
		}
	}
}

func netModel() model {
	m := testModel()
	m.net = netRow{
		name: "edge", driver: "bridge", subnet: "172.18.0.0/16",
		members: []netMember{
			{container: "komizo-caddy", aliases: []string{"caddy"}},
			{container: "blog-web-1", aliases: []string{"blog-web"}},
			{container: "shop-web-1", aliases: []string{"shop-web"}},
		},
	}
	return m
}

func TestServerScreenListsWhatIsAttached(t *testing.T) {
	v := send(netModel(), "s").View()
	for _, want := range []string{"edge", "bridge", "172.18.0.0/16", "komizo-caddy", "blog-web"} {
		if !strings.Contains(v, want) {
			t.Errorf("server screen is missing %q", want)
		}
	}
	if !strings.Contains(strings.ToLower(v), "no problems") {
		t.Error("a healthy box should say so, not leave you to infer it from a list")
	}
}

func TestDuplicateAliasesAreDetected(t *testing.T) {
	// The failure this whole screen exists for: two apps whose compose both
	// call a service "web", so both answer to "web" and traffic splits.
	n := netRow{name: "edge", members: []netMember{
		{container: "blog-web-1", aliases: []string{"web", "blog-web"}},
		{container: "shop-web-1", aliases: []string{"web", "shop-web"}},
	}}
	d := n.duplicateAliases()
	if len(d) != 1 {
		t.Fatalf("expected exactly one clash, got %v", d)
	}
	if len(d["web"]) != 2 {
		t.Errorf("both containers should be named in the clash, got %v", d["web"])
	}
	// The unique ones must not be reported.
	if _, bad := d["blog-web"]; bad {
		t.Error("a unique alias was reported as a clash")
	}
}

func TestClashIsShownOnTheNetworkScreenAndTheList(t *testing.T) {
	m := netModel()
	m.net.members = []netMember{
		{container: "blog-web-1", aliases: []string{"web"}},
		{container: "shop-web-1", aliases: []string{"web"}},
	}
	if !strings.Contains(m.View(), "alias clash") {
		t.Error("a clash should be visible on the list, which is where people live")
	}
	v := send(m, "s").View()
	if !strings.Contains(strings.ToLower(v), "alias clash") {
		t.Error("the server screen should name the clash")
	}
	if !strings.Contains(v, "aliases: [myapp-web]") {
		t.Error("it should show the fix, not just the problem")
	}
}

func TestAppPublishingRoutesButNotAttachedIsFlagged(t *testing.T) {
	// The other cause of the same 502, with the opposite fix.
	m := netModel()
	m.net.members = []netMember{{container: "komizo-caddy", aliases: []string{"caddy"}}}
	v := send(m, "s").View()
	if !strings.Contains(v, "not on this network") {
		t.Error("an app with routes but no network attachment should be called out")
	}
	if !strings.Contains(v, "blog") {
		t.Error("it should name the app")
	}
	// shop has no routes in testModel, so it is not expected to be attached.
	if strings.Contains(v, "shop") {
		t.Error("an app that publishes no routes should not be reported as missing")
	}
}

func TestServerScreenWithNoNetwork(t *testing.T) {
	m := netModel()
	m.net = netRow{}
	v := send(m, "s").View()
	if !strings.Contains(v, "none") {
		t.Error("a box with no network should say so")
	}
	if !strings.Contains(v, "press u") {
		t.Error("it should point at the fix")
	}
}

func TestParsesRealDockerOutput(t *testing.T) {
	// Captured verbatim from `docker network inspect` + `docker inspect` against
	// a live daemon, with two containers deliberately sharing an alias. Pinned
	// as a fixture because the whole clash check rests on this exact shape.
	out := strings.Join([]string{
		"net\tkomizo-test-edge\tbridge\t172.22.0.0/16",
		"netmember\tkomizo-t-blog\tweb,blog-web",
		"netmember\tkomizo-t-shop\tweb,shop-web",
	}, "\n")
	_, _, _, n, _ := parseInventory(out)
	if n.name != "komizo-test-edge" || n.driver != "bridge" || n.subnet != "172.22.0.0/16" {
		t.Fatalf("network meta parsed wrong: %+v", n)
	}
	if len(n.members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(n.members))
	}
	d := n.duplicateAliases()
	if len(d) != 1 || len(d["web"]) != 2 {
		t.Errorf("the shared 'web' alias should be the one clash, got %v", d)
	}
}

func TestUpdatingTheServerDoesNotAskAboutTheProxy(t *testing.T) {
	// The first-run form's only question is whether to install a proxy. Reusing
	// it for a routine Docker update would mean a stray enter installs one on a
	// box that deliberately has none.
	m := testModel()
	m.proxy = proxyRow{} // no proxy on this box, by choice
	m = send(m, "s", "u")
	if m.scr == screenInit {
		t.Fatal("update must not reopen the first-run form; that would re-ask the proxy question")
	}
	if m.scr != screenConfirm {
		t.Fatalf("update should confirm first, got %v", m.scr)
	}
	v := m.View()
	if !strings.Contains(v, "Docker") {
		t.Error("the confirmation should say what it actually does")
	}
	if !strings.Contains(v, "proxy is not touched") {
		t.Error("it should say the proxy is left alone, since that is the surprise it prevents")
	}
	if !strings.Contains(v, "apps keep running") {
		t.Error("it should say apps are unaffected")
	}
}

func TestFirstRunStillAsksAboutTheProxy(t *testing.T) {
	// On a bare box the question belongs: you are defining the shape of it.
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40
	next, _ := m.Update(appsMsg{srv: serverRow{state: "bare"}})
	m = next.(model)
	if m.scr != screenInit {
		t.Fatalf("a bare server should still open the init form, got %v", m.scr)
	}
	if !strings.Contains(m.View(), "reverse proxy") {
		t.Error("first run should still ask whether to install a proxy")
	}
}

// --- rendering ------------------------------------------------------------

func TestColumnsAlignWhenCellsAreStyled(t *testing.T) {
	// Columns used to be measured with len(), which counts ANSI escape bytes
	// the terminal never draws. One dimmed cell knocked the rest of the row
	// eight columns out of line.
	//
	// Asserted as a property: styling a cell must not change the layout at all.
	plain := [][]string{
		{"APP", "VERSION", "UP"},
		{"blog", "a1b2c3d4e5f6", "3"},
		{"shop", "never deployed", "0"},
	}
	styled := [][]string{
		{"APP", "VERSION", "UP"},
		{"blog", "a1b2c3d4e5f6", okStyle.Render("3")},
		{"shop", dimStyle.Render("never deployed"), errStyle.Render("0")},
	}
	if a, b := stripANSI(table(plain, -1)), stripANSI(table(styled, -1)); a != b {
		t.Errorf("styling changed the layout:\nplain:\n%s\nstyled:\n%s", a, b)
	}
}

func TestWarningsAndErrorsLookDifferent(t *testing.T) {
	// Both were plain bold once, so the one moment the difference matters --
	// "this might be a problem" versus "this is broken" -- looked identical.
	//
	// Compared on the styles rather than on rendered output: lipgloss drops
	// colour when there is no terminal, which is exactly the case under `go
	// test`, so rendering here would compare two uncoloured strings and pass.
	if warnStyle.GetForeground() == errStyle.GetForeground() {
		t.Error("a warning and an error must not use the same colour")
	}
	// Shape as well as colour, so both survive a colourless terminal and are
	// distinguishable without colour vision.
	for _, pair := range [][2]string{{"ok", "err"}, {"ok", "warn"}, {"warn", "err"}} {
		if stripANSI(dot(pair[0])) == stripANSI(dot(pair[1])) {
			t.Errorf("dot(%q) and dot(%q) use the same glyph", pair[0], pair[1])
		}
	}
}

func TestNoScreenHasTrailingWhitespace(t *testing.T) {
	// Trailing runs of spaces are invisible until someone selects the text, and
	// they come for free from styling a multi-line string.
	m := netModel()
	screens := map[string]string{
		"list":    m.View(),
		"detail":  func() model { x := send(m, "enter"); return x }().View(),
		"server":  func() model { x := send(m, "s"); return x }().View(),
		"add":     func() model { x := send(m, "a"); return x }().View(),
		"confirm": func() model { x := send(m, "x"); return x }().View(),
	}
	for name, out := range screens {
		for i, ln := range strings.Split(out, "\n") {
			if ln != strings.TrimRight(ln, " ") {
				t.Errorf("%s line %d has trailing whitespace: %q", name, i+1, ln)
			}
		}
	}
}

func TestHelpIsAlwaysOnScreen(t *testing.T) {
	// The keys are discoverable or they do not exist.
	m := netModel()
	for name, out := range map[string]string{
		"list":   m.View(),
		"server": send(m, "s").View(),
		"add":    send(m, "a").View(),
	} {
		if !strings.Contains(out, "esc") && !strings.Contains(out, "quit") {
			t.Errorf("%s screen shows no key hints", name)
		}
	}
}

func TestWrapCountsColumnsNotBytes(t *testing.T) {
	// An em-dash is three bytes and one column.
	got := wrap("a — b", 5)
	if len(got) != 1 {
		t.Errorf("expected one line, got %d: %q", len(got), got)
	}
}

// stripANSI removes escape sequences so a test can assert on what is drawn.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// --- why a connection failed ----------------------------------------------

func TestSSHFailuresAreToldApart(t *testing.T) {
	// Every one of these exits 255, so the stderr text is the only signal.
	// Captured verbatim from OpenSSH against a real sshd.
	for _, c := range []struct {
		raw  string
		want reachKind
		why  string
	}{
		{"Host key verification failed.", reachUnknownHost,
			"a server you just created is the normal case, not an auth problem"},
		{"root@1.2.3.4: Permission denied (publickey,password,keyboard-interactive).", reachAuth,
			"the key really was refused"},
		{"ssh: connect to host 1.2.3.4 port 22: Connection refused", reachNetwork, "nothing listening"},
		{"ssh: connect to host 1.2.3.4 port 22: Connection timed out", reachNetwork, "firewalled"},
		{"ssh: Could not resolve hostname nope.invalid: Name or service not known", reachNetwork, "bad name"},
		{"@@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@@\nHost key verification failed.",
			reachChangedHost,
			"a changed key ALSO prints 'verification failed' -- it must not be mistaken for a first meeting"},
		{"Connection closed by 1.2.3.4 port 22", reachOther, "unknown, so pass ssh's own words through"},
	} {
		if got := classify(c.raw); got != c.want {
			t.Errorf("classify(%q) = %v, want %v -- %s", c.raw, got, c.want, c.why)
		}
	}
}

func TestUnknownHostDoesNotBlameTheKey(t *testing.T) {
	// The bug this replaced: a fresh server produced "cannot SSH in as root
	// without a password" and sent people to ssh-copy-id, which is not the fix.
	tgt := target{user: "root", host: "1.2.3.4", port: 22}
	msg := reachResult{kind: reachUnknownHost}.explain(tgt).Error()
	if strings.Contains(msg, "ssh-copy-id") {
		t.Error("an unknown host key is not a credentials problem; do not suggest ssh-copy-id")
	}
	for _, want := range []string{"never connected", "known_hosts", "ssh root@1.2.3.4", "--accept-host-key"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message is missing %q:\n%s", want, msg)
		}
	}
}

func TestChangedHostKeyIsNotOfferedAsRoutine(t *testing.T) {
	// The one case that might be an attack. It must not read like the others.
	msg := reachResult{kind: reachChangedHost}.explain(target{user: "root", host: "h", port: 22}).Error()
	if !strings.Contains(msg, "CHANGED") || !strings.Contains(msg, "impersonating") {
		t.Errorf("a changed host key must be called out, got:\n%s", msg)
	}
	if strings.Contains(msg, "--accept-host-key") {
		t.Error("komizo must never offer to auto-accept a key that CHANGED")
	}
}

func TestAuthFailureStillSuggestsSshCopyId(t *testing.T) {
	msg := reachResult{kind: reachAuth}.explain(target{user: "root", host: "h", port: 22}).Error()
	if !strings.Contains(msg, "ssh-copy-id root@h") {
		t.Errorf("a real auth failure should still point at ssh-copy-id, got:\n%s", msg)
	}
}

func TestInitAsksOneThingOnly(t *testing.T) {
	// It asked for a network name, then whether to install the proxy. Both are
	// gone: the network is the worst thing to decide on an empty box, and the
	// proxy is what every app is reached through, so "no" only meant finding
	// out later. Now it is a statement and one decision.
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40
	next, _ := m.Update(appsMsg{srv: serverRow{state: "bare"}})
	m = next.(model)
	if m.scr != screenInit {
		t.Fatalf("a bare server should open the init screen, got %v", m.scr)
	}
	v := m.View()
	if !strings.Contains(v, "enter") || !strings.Contains(v, "set it up") {
		t.Error("the init screen should offer exactly one action")
	}
	// No question about the proxy survives anywhere on it.
	for _, gone := range []string{"[yes]", "reverse proxy?", "tab"} {
		if strings.Contains(v, gone) {
			t.Errorf("init screen still contains %q -- it should ask nothing", gone)
		}
	}
	// And enter goes straight to work.
	m = send(m, "enter")
	if m.scr != screenRunning {
		t.Errorf("enter should start the setup, got %v", m.scr)
	}
}

func TestInitAlwaysInstallsTheProxy(t *testing.T) {
	// There is no longer a path through init that leaves a box without one.
	if o := (initOpts{network: defaultNetwork, image: defaultProxy}); o.network == "" || o.image == "" {
		t.Error("init must still supply the defaults it stopped asking for")
	}
	src, err := os.ReadFile("init.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), `"proxy", true`) || strings.Contains(string(src), "o.proxy") {
		t.Error("the --proxy opt-out is back; init is meant to always install it")
	}
}

func TestResultNeverPrintsTheKeyItself(t *testing.T) {
	// This screen ends up in screenshots and scrollback. The path may appear;
	// the contents may not, on any code path.
	base := addResult{app: "ormos", keyPath: "/home/you/.ssh/deploy_ormos_1.2.3.4",
		knownHosts: "1.2.3.4 ssh-ed25519 AAAAC3Nza"}
	for _, r := range []addResult{
		base,
		{app: base.app, keyPath: base.keyPath, knownHosts: base.knownHosts, onClipboard: resultKey},
		{app: base.app, keyPath: base.keyPath, knownHosts: base.knownHosts, copyErr: "no clipboard tool found"},
		{app: base.app, keyPath: base.keyPath, knownHosts: base.knownHosts, rotated: true},
	} {
		v := r.view()
		for _, forbidden := range []string{"PRIVATE KEY", "BEGIN OPENSSH"} {
			if strings.Contains(v, forbidden) {
				t.Errorf("the result screen must never render key material (%q)", forbidden)
			}
		}
		if !strings.Contains(v, base.keyPath) {
			t.Error("the path should be shown, so you can find the key")
		}
	}
}

func TestResultDoesNotLookLikeTheValueIsACatCommand(t *testing.T) {
	// "cat /home/..." sat alone under SSH_DEPLOY_KEY, which reads like a value
	// and invited pasting that literal string into the secret.
	v := addResult{app: "ormos", keyPath: "/k", knownHosts: "h k b"}.view()
	if !strings.Contains(v, "contents not shown") {
		t.Error("the screen must say the value is the file's contents, not the line shown")
	}
	// The host key IS shown in full -- it is not confidential, and hiding it
	// would make a CI mismatch unreadable.
	if !strings.Contains(v, "h k b") {
		t.Error("known_hosts should be shown in full, ready to paste")
	}
}

func TestBothValuesAreSelectableAndCopyable(t *testing.T) {
	// Both have to reach GitHub. Copying one does not finish the job, so each
	// keeps its own state and the screen must not claim otherwise.
	r := &addResult{app: "ormos", keyPath: "/k", knownHosts: "h k b"}
	if r.cursor != resultKey {
		t.Error("the key should be selected first; it is the one you paste first")
	}

	m := testModel()
	m.scr = screenResult
	m.run = newRunState("x")
	m.run.done, m.run.result = true, r

	m = send(m, "down")
	if m.run.result.cursor != resultHosts {
		t.Fatalf("down should select the host keys, got %d", m.run.result.cursor)
	}
	m = send(m, "down", "down")
	if m.run.result.cursor != resultItems-1 {
		t.Error("the cursor must not run past the last value")
	}
	m = send(m, "up", "up", "up")
	if m.run.result.cursor != 0 {
		t.Error("the cursor must not run above the first value")
	}
}

func TestKnownHostsCopiesItsValueNotAPath(t *testing.T) {
	// The key is copied from its file so its contents are never held here.
	// known_hosts is already in hand and is not confidential, so it copies
	// directly -- and must end with a newline, or appending to the variable in
	// GitHub joins two entries into one unusable line.
	if !clipboardAvailable() {
		t.Skip("no clipboard tool")
	}
	r := addResult{keyPath: "/nonexistent", knownHosts: "1.2.3.4 ssh-ed25519 AAAA", cursor: resultHosts}
	if err := r.copySelected(); err != nil {
		t.Fatalf("copying the host keys should not touch the filesystem: %v", err)
	}
}

func TestOnlyOneValueIsEverMarked(t *testing.T) {
	// There is one clipboard. Marking every value that has ever been copied
	// claims two things are on it at once, and reads as the mark being stuck to
	// the first row.
	mark := func(r addResult) (onKey, onHosts bool) {
		for _, ln := range strings.Split(r.view(), "\n") {
			if strings.Contains(ln, "clipboard") && strings.Contains(ln, "SSH_DEPLOY_KEY") {
				onKey = true
			}
			if strings.Contains(ln, "clipboard") && strings.Contains(ln, "SSH_KNOWN_HOSTS") {
				onHosts = true
			}
		}
		return
	}
	base := addResult{app: "a", keyPath: "/k", knownHosts: "h k b", onClipboard: -1}

	if k, h := mark(base); k || h {
		t.Error("nothing has been copied yet, so nothing should be marked")
	}
	k, h := mark(addResult{app: "a", keyPath: "/k", knownHosts: "h k b", onClipboard: resultKey})
	if !k || h {
		t.Errorf("only the key should be marked, got key=%v hosts=%v", k, h)
	}
	k, h = mark(addResult{app: "a", keyPath: "/k", knownHosts: "h k b", onClipboard: resultHosts})
	if k || !h {
		t.Errorf("the mark must MOVE, not accumulate: key=%v hosts=%v", k, h)
	}
}

func TestCopyingTheSecondReplacesTheFirst(t *testing.T) {
	m := testModel()
	m.scr = screenResult
	m.run = newRunState("x")
	m.run.done = true
	m.run.result = &addResult{app: "a", keyPath: "/nonexistent-so-copy-fails",
		knownHosts: "h k b", onClipboard: -1}

	// Copy the host keys (works: no file involved).
	m = send(m, "down", "c")
	if m.run.result.onClipboard != resultHosts {
		t.Fatalf("host keys should be on the clipboard, got %d", m.run.result.onClipboard)
	}
	// Now a failing copy must not leave the previous value claimed.
	m = send(m, "up", "c")
	if m.run.result.copyErr == "" {
		t.Fatal("copying a missing key file should report an error")
	}
	if m.run.result.onClipboard != -1 {
		t.Error("a failed copy must not leave the previous value marked as current")
	}
}

func TestWaylandCopyForcesPlainText(t *testing.T) {
	// wl-copy sniffs its input and advertises a matching type. Given a private
	// key it offers ONLY application/x-pem-file, so every text field asks for
	// text/plain, finds nothing, and pastes nothing -- while the copy itself
	// reports success. Forcing the type is what makes the key pasteable.
	//
	// Asserted on the argv rather than the clipboard so it holds on machines
	// with no compositor, e.g. CI.
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	argv := clipboardCmd()
	if argv == nil {
		t.Skip("no clipboard tool installed")
	}
	if !strings.Contains(argv[0], "wl-copy") {
		t.Skip("wl-copy not the chosen tool here")
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--type text/plain") {
		t.Errorf("wl-copy must be told the type, got %q", joined)
	}
}

func TestDetailScreenHandlesEveryKeyItAdvertises(t *testing.T) {
	// The help line was copied from the list; the handler was not, so the
	// detail screen offered rotate and remove and did nothing for either.
	for _, k := range []string{"c", "r", "x"} {
		m := send(testModel(), "enter", k)
		if m.scr == screenDetail {
			t.Errorf("%q is advertised on the detail screen but does nothing", k)
		}
	}
}

func TestConfigImageIsEditable(t *testing.T) {
	// The pin is the trust anchor, so a wrong value fails at deploy time with a
	// registry "not found" -- which reads like a build problem, not a setting.
	m := send(testModel(), "enter", "c")
	if m.scr != screenConfigForm {
		t.Fatalf("'c' should open the config image form, got %v", m.scr)
	}
	v := m.View()
	if !strings.Contains(v, "ghcr.io/you/blog-config") {
		t.Error("the form should be pre-filled with the current value")
	}
	if !strings.Contains(v, "deploy key is untouched") {
		t.Error("it should say the GitHub values do not change")
	}

	// A tag is the mistake worth catching, same as when adding.
	for _, r := range ":v1" {
		m = send(m, string(r))
	}
	m = send(m, "enter")
	if m.scr != screenConfigForm || !strings.Contains(m.configForm.problem, "tag") {
		t.Errorf("a tag should be rejected, got problem=%q scr=%v", m.configForm.problem, m.scr)
	}
}

func TestUnchangedConfigImageDoesNothing(t *testing.T) {
	// Pressing enter without editing should not re-run setup on the server.
	m := send(testModel(), "enter", "c", "enter")
	if m.scr != screenDetail {
		t.Errorf("an unchanged value should just go back, got %v", m.scr)
	}
}

func TestConfigChangeResultDoesNotAskForAPaste(t *testing.T) {
	// Nothing in GitHub changed, so the usual "add these to the repo" screen
	// would be actively misleading.
	v := addResult{app: "ormos", keyPath: "/k", knownHosts: "h k b",
		changedConfig: "ghcr.io/nicodes/ormos-config", onClipboard: -1}.view()
	if strings.Contains(v, "Add these to the repo") {
		t.Error("a config change must not tell you to paste values into GitHub")
	}
	for _, want := range []string{"ghcr.io/nicodes/ormos-config", "Nothing in GitHub changed"} {
		if !strings.Contains(v, want) {
			t.Errorf("result is missing %q", want)
		}
	}
}
