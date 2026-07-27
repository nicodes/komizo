package main

import (
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
		"netmember\tncicd-caddy\tcaddy,ncicd-caddy",
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
	// /srv/_proxy is ncicd's own; an app taking that name would collide with it
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
	for _, want := range []string{"not set up yet", "Docker", "reverse proxy"} {
		if !strings.Contains(v, want) {
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

func TestInitScreenDefaultsToInstallingTheProxy(t *testing.T) {
	o := newInitForm().opts()
	if !o.proxy {
		t.Error("the proxy should be on by default; it is what makes HTTPS work")
	}
	if o.network != defaultNetwork {
		t.Errorf("network default is wrong: %q", o.network)
	}
}

func TestProxyCanBeTurnedOffWithoutTyping(t *testing.T) {
	// A yes/no answer is a choice field, not a text box -- typing "no" into a
	// text box is a way to get "n" or "No" wrong.
	f := newInitForm()
	if len(f.fields[0].choices) == 0 {
		t.Fatal("the proxy field should be a choice, not free text")
	}
	f.fields[0].cycle(1)
	if f.opts().proxy {
		t.Error("cycling the choice should have turned the proxy off")
	}
	f.fields[0].cycle(1) // wraps back
	if !f.opts().proxy {
		t.Error("cycling should wrap round to yes")
	}
}

func TestInitAsksExactlyOneQuestion(t *testing.T) {
	// The network name used to be asked here. A fresh box is the worst moment
	// to ask: you cannot know whether the default collides, and changing it
	// later means editing every app's compose.yml.
	f := newInitForm()
	if len(f.fields) != 1 {
		t.Errorf("init should ask one question, got %d: %+v", len(f.fields), f.fields)
	}
	if o := f.opts(); o.network != defaultNetwork || o.image != defaultProxy {
		t.Errorf("init must still supply the defaults it stopped asking for: %+v", o)
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
	for _, f := range newInitForm().fields {
		if strings.Contains(strings.ToLower(f.label), "email") {
			t.Errorf("init form still asks for %q", f.label)
		}
	}
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
	for _, want := range []string{"/srv/_proxy/compose.yml", "-p ncicd-proxy", "restart"} {
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
			{container: "ncicd-caddy", aliases: []string{"caddy"}},
			{container: "blog-web-1", aliases: []string{"blog-web"}},
			{container: "shop-web-1", aliases: []string{"shop-web"}},
		},
	}
	return m
}

func TestServerScreenListsWhatIsAttached(t *testing.T) {
	v := send(netModel(), "s").View()
	for _, want := range []string{"edge", "bridge", "172.18.0.0/16", "ncicd-caddy", "blog-web"} {
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
	m.net.members = []netMember{{container: "ncicd-caddy", aliases: []string{"caddy"}}}
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
		"net\tncicd-test-edge\tbridge\t172.22.0.0/16",
		"netmember\tncicd-t-blog\tweb,blog-web",
		"netmember\tncicd-t-shop\tweb,shop-web",
	}, "\n")
	_, _, _, n, _ := parseInventory(out)
	if n.name != "ncicd-test-edge" || n.driver != "bridge" || n.subnet != "172.22.0.0/16" {
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
