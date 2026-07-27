package main

import (
	"os"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func testModel() model {
	m := newModel(target{user: "root", host: "box.example.com", port: 22})
	m.width, m.height = 100, 40
	m.scr = screenList
	m.apps = []appRow{
		{name: "blog", user: "komizo-blog", dir: "/srv/blog", version: "a1b2c3d4e5f6a7b8", running: "3", image: "ghcr.io/you/blog-config",
			routes: []routeRow{{app: "blog", sites: "blog.example.com", upstream: "blog-web"}}},
		{name: "shop", user: "komizo-shop", dir: "/srv/shop", version: "none", running: "0", image: "ghcr.io/you/shop-config"},
	}
	m.proxy = proxyRow{installed: true, state: "running", network: "edge",
		image: "caddy:2", status: "Up 3 hours"}
	m.srv = serverRow{state: "ready", docker: "Docker version 26.1.3"}
	m.loaded = true
	// The shared network, so a route's upstream resolves to a container the way
	// it does on a real box. Without it every route looks orphaned, which is a
	// state worth testing but not the default one.
	m.net = netRow{name: "edge", driver: "bridge", members: []netMember{
		{container: "komizo-caddy", aliases: []string{"caddy", "komizo-caddy"}},
		{container: "blog-web-1", aliases: []string{"web", "blog-web"}},
	}}
	// Where the first inventory would leave it: on the first app, not on the
	// box rows above.
	m.cursor = m.firstAppRow()
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

// rowOf finds the cursor position of the first row of a given kind, so tests
// name what they are selecting instead of hard-coding an index that moves every
// time a row is added.
func rowOf(m model, k focusKind) int {
	for i, f := range m.focusItems() {
		if f.kind == k {
			return i
		}
	}
	return -1
}

func send(m model, keys ...string) model {
	for _, k := range keys {
		next, _ := m.Update(key(k))
		m = next.(model)
	}
	return m
}

func TestListShowsEveryApp(t *testing.T) {
	// Routes hang off the container serving them, so an app that publishes one
	// has a container -- which is true on a real box too: the caddy fragment
	// arrives with the deploy that creates them.
	m := testModel()
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 2 days"},
	}
	v := stripANSI(m.View())
	for _, want := range []string{"blog", "blog.example.com", "shop"} {
		if !strings.Contains(v, want) {
			t.Errorf("list view is missing %q", want)
		}
	}
	// The config image is on the app's own row: it is what the host is pinned
	// to, and the one piece of an app's setup that is neither derivable nor
	// visible from its containers.
	if !strings.Contains(v, "ghcr.io/you/blog-config") {
		t.Errorf("the app row should carry its config image:\n%s", v)
	}
	// The directory is not. It is /srv/<app> unless someone overrode it, so it
	// is a column that says the same thing as the one beside it.
	if strings.Contains(v, "/srv/blog") {
		t.Error("the list should stay compact; the directory is derivable")
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
	// It runs over the box rows and the app rows together, so the bounds are
	// the focus list rather than the app count.
	m := send(testModel(), "up", "up", "up", "up", "up")
	if m.cursor != 0 {
		t.Errorf("cursor went above the first row: %d", m.cursor)
	}
	for i := 0; i < 20; i++ {
		m = send(m, "down")
	}
	if want := len(m.focusItems()) - 1; m.cursor != want {
		t.Errorf("cursor went past the last row: %d, want %d", m.cursor, want)
	}
}

func TestCursorReachesTheBoxRowsAndEveryContainer(t *testing.T) {
	// The point of the flat list: everything on the page is reachable with the
	// arrow keys, not just the app rows.
	m := testModel()
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 3 hours"},
	}
	m.srv.hostKeys = [][2]string{{"ssh-ed25519", "AAAA"}}

	var kinds []focusKind
	for _, f := range m.focusItems() {
		kinds = append(kinds, f.kind)
	}
	want := []focusKind{focusServer, focusHosts, focusProxy, focusApp, focusContainer, focusApp}
	if len(kinds) != len(want) {
		t.Fatalf("focus list = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("row %d is kind %v, want %v", i, kinds[i], want[i])
		}
	}

	// A container row is not an app row: the app-wide keys must not fire from
	// it, or "remove" beside one container's name reads as removing that
	// container.
	m.cursor = 4
	if got := m.selectedApp(); got != -1 {
		t.Errorf("a container row must not select an app, got %d", got)
	}
	if c := m.focusedContainer(); c == nil || c.name != "blog-web-1" {
		t.Errorf("focusedContainer did not find the container: %+v", c)
	}
	// An app row is not a container.
	m.cursor = 3
	if m.focusedContainer() != nil {
		t.Error("an app row must not report a focused container")
	}
	if got := m.selectedApp(); got != 0 {
		t.Errorf("an app row should select its app, got %d", got)
	}
}

func TestAnAppIsOneRow(t *testing.T) {
	// The detail screen is gone and nothing replaced it with an expanding
	// block: an app is a row, and the row carries what cannot be worked out
	// from the containers under it.
	m := testModel()
	m.cursor = rowOf(m, focusApp)
	v := stripANSI(m.View())

	for _, want := range []string{"blog", "ghcr.io/you/blog-config"} {
		if !strings.Contains(v, want) {
			t.Errorf("the app row should show %q:\n%s", want, v)
		}
	}
	// Everything derivable from the app's name is left off: the account, the
	// directory, the two privileged commands. `komizo list` prints them.
	for _, gone := range []string{"komizo-blog", "deploy-blog", "set-secret-blog", "/srv/blog"} {
		if strings.Contains(v, gone) {
			t.Errorf("%q is derivable and should not be on the list", gone)
		}
	}
	// Selecting a different app must not change how much of either is shown.
	before := strings.Count(v, "\n")
	m.cursor++
	if after := strings.Count(stripANSI(m.View()), "\n"); after != before {
		t.Errorf("moving the cursor changed the page height: %d -> %d", before, after)
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
	// Enter advances while there is a field below, and submits on the last one.
	// "known as" is now always present, so reaching the submit takes one more.
	m = send(m, "enter", "enter")
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
	m = send(m, "enter", "enter")
	if m.scr != screenAddForm || m.form.problem == "" {
		t.Error("a space in the app name should be rejected")
	}
}

func TestRemoveRequiresTypingTheAppName(t *testing.T) {
	m := send(testModel(), "x")
	if m.prompt == nil {
		t.Fatal("'x' did not ask anything")
	}
	if m.scr != screenList {
		t.Errorf("the question should not leave the list, got %v", m.scr)
	}
	v := m.View()
	// The list is still behind it -- that is the point of asking in the footer.
	if !strings.Contains(stripANSI(v), "ghcr.io/you/blog-config") {
		t.Error("the app list should stay visible while the question is asked")
	}
	for _, want := range []string{"/srv/blog", "Cannot be undone"} {
		if !strings.Contains(m.prompt.detail, want) {
			t.Errorf("the question should spell out %q", want)
		}
	}
	// Enter alone must not be enough.
	m = send(m, "enter")
	if m.prompt == nil {
		t.Error("enter without typing the name should not start the removal")
	}
	m = send(m, "b", "l", "o", "enter")
	if m.prompt == nil {
		t.Error("a partial name should not start the removal")
	}
	// And "y" must not be a shortcut past it -- it is a letter here.
	m = send(m, "y")
	if m.prompt == nil || m.prompt.typed != "bloy" {
		t.Error("y should be typed, not treated as confirmation")
	}
}

func TestRotateDoesNotRequireTyping(t *testing.T) {
	m := send(testModel(), "r")
	if m.prompt == nil {
		t.Fatal("'r' did not ask anything")
	}
	if m.prompt.kind != promptConfirm {
		t.Error("rotating a key does not delete data; it should not demand typing")
	}
	if !strings.Contains(m.prompt.detail, "stops working") {
		t.Error("the rotate question should warn that the old key dies immediately")
	}
	// One key answers it.
	if next := send(m, "y"); next.prompt != nil {
		t.Error("y should answer a plain confirmation")
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
		"app\tblog\tcd-blog\t/srv/blog\ta1b2\t2\tghcr.io/you/blog-config",
		"route\tblog\tblog.example.com\tblog-web",
		"app\tworker\tcd-worker\t/srv/worker\tnone\t0\tghcr.io/you/worker-config",
		"proxy\trunning\tedge\tcaddy:2\tUp 3 hours\t2026-07-27T09:00:00Z\t0001-01-01T00:00:00Z\t0",
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
	if got := apps[0].allRoutes(); len(got) != 1 || got[0] != "blog.example.com" {
		t.Errorf("routes not parsed: %q", got)
	}
	if apps[0].routes[0].upstream != "blog-web" {
		t.Errorf("upstream not parsed: %q", apps[0].routes[0].upstream)
	}
	// An app with no routes is normal -- a worker or a cron job.
	if got := apps[1].allRoutes(); len(got) != 0 {
		t.Errorf("expected no routes for worker, got %q", got)
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

func TestTheBoxIsAlwaysOnScreen(t *testing.T) {
	// Docker, the network and the proxy had a page each, then one page, and are
	// now the block above the app list. A stopped proxy used to stay invisible
	// for as long as it took someone to think of pressing a key.
	v := netModel().View()
	for _, want := range []string{
		"Server",
		"root@box.example.com",  // the address, which used to live in the header
		"Docker version 26.1.3", // docker
		"edge", "bridge",        // network
		"running", "caddy:2", // proxy
		"known_hosts",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("the list is missing %q", want)
		}
	}
}

func TestAStoppedProxyIsCalledOutWithoutNavigating(t *testing.T) {
	m := netModel()
	m.proxy = proxyRow{installed: true, state: "stopped", network: "edge",
		image: "caddy:2", status: "Exited (0) 5 minutes ago"}
	v := m.View()
	if !strings.Contains(v, "stopped") {
		t.Error("a stopped proxy is the loudest possible problem; it must be on the list")
	}
	// What it means for the apps is the red dot on every one of them, plus the
	// proxy's own row saying stopped -- there is no summary block any more.
	m.cursor = rowOf(m, focusProxy)
	if got := m.enterLabel(); got != "start" {
		t.Errorf("enter on a stopped proxy should offer to start, got %q", got)
	}

	m.proxy = proxyRow{}
	v = m.View()
	if !strings.Contains(v, "not installed") {
		t.Error("a box with no proxy should say so, not show nothing")
	}
	// The offer is on the proxy row, which is where someone reading "not
	// installed" is already looking.
	m.cursor = rowOf(m, focusProxy)
	if m.cursor < 0 {
		// No proxy means no proxy row; the offer moves to whatever is selected.
		if !strings.Contains(m.View(), "install a proxy") {
			t.Error("it should offer to install one")
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

func TestInstallingTheProxyIsConfirmedAndCarriesTheCurrentSettings(t *testing.T) {
	// The settings form is gone: it asked two questions to reach a button that
	// almost always wanted the values already on screen. What replaced it must
	// therefore carry those values forward rather than reverting to defaults.
	m := netModel()
	m.proxy = proxyRow{installed: true, state: "running", network: "web", image: "caddy:2.8"}
	m.net = netRow{name: "web", driver: "bridge"}
	m = send(m, "p")
	if m.prompt == nil {
		t.Fatal("'p' should ask before recreating the container")
	}
	d := m.prompt.question + " " + m.prompt.detail
	for _, want := range []string{"caddy:2.8", "Certificates survive"} {
		if !strings.Contains(d, want) {
			t.Errorf("the question should mention %q: %q", want, d)
		}
	}
}

func TestInstallingOnABoxWithNoProxyExplainsWhatItIs(t *testing.T) {
	m := netModel()
	m.proxy = proxyRow{}
	m = send(m, "p")
	if m.prompt == nil {
		t.Fatal("'p' should ask")
	}
	if !strings.Contains(m.prompt.question, "Install") {
		t.Error("on a box with no proxy it should offer to install, not reinstall")
	}
}

func TestALogGetsTheWholeWindow(t *testing.T) {
	// It used to open as a pane under the list, so the thing you came to read
	// got whatever space was left over -- usually a dozen lines on a screen
	// where the list you had stopped looking at took twenty.
	m := netModel()
	m.width, m.height = 90, 30
	m.cursor = rowOf(m, focusProxy)
	m, cmd := sendCmd(m, "l")
	if m.scr != screenLogs {
		t.Fatalf("'l' should open the log window, got %v", m.scr)
	}
	if cmd == nil {
		t.Error("it should fetch the log")
	}
	if m.logsOf != proxyContainer {
		t.Errorf("it should be the proxy's log, got %q", m.logsOf)
	}
	// Always a fresh fetch from the top: reopening a log after something has
	// happened to it is the common case.
	if m.logs != "" || m.logScroll != 0 {
		t.Error("opening a log should not show the previous one's text or position")
	}

	// The window has the same title and a footer in the same place as the list.
	m.logs = "line one\nline two"
	v := stripANSI(m.View())
	if !strings.Contains(v, "komizo") {
		t.Error("the log window should carry the same title")
	}
	if !strings.Contains(v, "esc") || !strings.Contains(v, "copy") {
		t.Errorf("the footer should offer back and copy:\n%s", v)
	}

	// And esc returns to the list.
	if back := send(m, "esc"); back.scr != screenList {
		t.Errorf("esc should go back, got %v", back.scr)
	}
}

func TestScrollingStopsAtBothEnds(t *testing.T) {
	// Scrolling past the last line into blank space is a way of losing the text
	// you were reading.
	m := netModel()
	m.scr, m.width, m.height = screenLogs, 90, 20
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, "line")
	}
	m.logs = strings.Join(lines, "\n")

	m = send(m, "up", "up", "up")
	if m.logScroll != 0 {
		t.Errorf("scrolled above the first line: %d", m.logScroll)
	}
	for i := 0; i < 200; i++ {
		m = send(m, "down")
	}
	if want := m.maxLogScroll(); m.logScroll != want {
		t.Errorf("scrolled past the end: %d, want %d", m.logScroll, want)
	}
	// G and g are the ends.
	if got := send(m, "g").logScroll; got != 0 {
		t.Errorf("g should go to the top, got %d", got)
	}
	if got := send(m, "G").logScroll; got != m.maxLogScroll() {
		t.Errorf("G should go to the bottom, got %d", got)
	}
	// A log that fits needs no scrolling at all.
	m.logs = "one\ntwo"
	if m.maxLogScroll() != 0 {
		t.Error("a log that fits should not scroll")
	}
}

func TestStoppedProxyIsShouted(t *testing.T) {
	m := netModel()
	m.proxy = proxyRow{installed: true, state: "stopped", network: "edge", status: "Exited (0) 5 minutes ago"}
	v := m.View()
	// Case-insensitive: the wording is a style choice, that it is called out is not.
	if !strings.Contains(strings.ToLower(v), "stopped") {
		t.Error("a stopped proxy should be unmissable")
	}

	// Docker's prose is gone: every row on the page now says what it is doing
	// and for how long, in one format. The exit code survives it.
	if !strings.Contains(stripANSI(v), "stopped") {
		t.Error("it should say the proxy is stopped")
	}
	// With the proxy selected, enter offers to start it rather than stop it.
	m.cursor = rowOf(m, focusProxy)
	if got := m.enterLabel(); got != "start" {
		t.Errorf("a stopped proxy should offer to start, got %q", got)
	}
}

func TestLogsRenderAndLateOnesAreIgnored(t *testing.T) {
	m := netModel()
	m.scr, m.logsOf, m.logsLabel = screenLogs, proxyContainer, "proxy"
	m.width, m.height = 90, 30
	next, _ := m.Update(logsMsg{container: proxyContainer, lines: "obtaining certificate\nchallenge failed"})
	m = next.(model)
	v := stripANSI(m.View())
	if !strings.Contains(v, "challenge failed") {
		t.Error("logs should render; they are usually the answer to a TLS problem")
	}
	if !strings.Contains(v, "proxy log") {
		t.Error("the window should say whose log it is")
	}

	// A fetch that lands after the cursor moved on must not overwrite the log
	// that was asked for second.
	next, _ = m.Update(logsMsg{container: "some-other-1", lines: "stale output"})
	if strings.Contains(stripANSI(next.(model).View()), "stale output") {
		t.Error("a log for a container we are no longer showing must be dropped")
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

func TestClashIsShownOnTheRowsItIsAbout(t *testing.T) {
	// Two containers answering to one name. Neither row looks wrong on its own
	// -- both are running -- and Caddy round-robins between them, so it fails
	// intermittently rather than outright. With the problems block gone, the
	// only place left to say so is the rows themselves.
	m := netModel()
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 2 days"},
	}
	m.net.members = []netMember{
		{container: "blog-web-1", aliases: []string{"web"}},
		{container: "shop-web-1", aliases: []string{"web"}},
	}
	v := stripANSI(m.View())
	if !strings.Contains(v, "alias clash: web") {
		t.Errorf("the clashing container's row should name the clash:\n%s", v)
	}

	// And a box without one says nothing about it.
	m.net.members = []netMember{{container: "blog-web-1", aliases: []string{"blog-web"}}}
	if strings.Contains(stripANSI(m.View()), "alias clash") {
		t.Error("a healthy box should not mention clashes at all")
	}
}

func TestServerScreenWithNoNetwork(t *testing.T) {
	m := netModel()
	m.net = netRow{}
	v := m.View()
	if !strings.Contains(v, "none") {
		t.Error("a box with no network should say so")
	}
	// The fix is re-running setup. It used to say "press u"; that key is gone,
	// and a hint naming a key that does nothing is worse than no hint.
	if !strings.Contains(stripANSI(v), "docker row") {
		t.Error("it should point at where the fix lives")
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
	m.cursor = rowOf(m, focusServer)
	m = send(m, "enter")
	if m.scr == screenInit {
		t.Fatal("update must not reopen the first-run form; that would re-ask the proxy question")
	}
	if m.prompt == nil {
		t.Fatal("update should ask first")
	}
	// Asserted on the text rather than the render: the footer wraps to the
	// terminal, so a phrase can straddle two lines and still be shown.
	d := m.prompt.question + " " + m.prompt.detail
	if !strings.Contains(d, "Docker") {
		t.Error("the question should say what it actually does")
	}
	if !strings.Contains(d, "proxy is not touched") {
		t.Error("it should say the proxy is left alone, since that is the surprise it prevents")
	}
	if !strings.Contains(d, "apps keep running") {
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
	plain := []treeRow{
		{idx: -1, cells: []string{"APP", "VERSION", "UP"}},
		{idx: 0, cells: []string{"blog", "a1b2c3d4e5f6", "3"}},
		{idx: 1, cells: []string{"shop", "never deployed", "0"}},
	}
	styled := []treeRow{
		{idx: -1, cells: []string{"APP", "VERSION", "UP"}},
		{idx: 0, cells: []string{"blog", "a1b2c3d4e5f6", okStyle.Render("3")}},
		{idx: 1, cells: []string{"shop", dimStyle.Render("never deployed"), errStyle.Render("0")}},
	}
	if a, b := stripANSI(tree(plain, -1)), stripANSI(tree(styled, -1)); a != b {
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
	// The three states share one glyph now, so colour is the only thing
	// telling them apart. The words beside it are the fallback -- "stopped",
	// "Exited (1) 2 minutes ago" -- which is why no status is ever a bare dot.
	if okStyle.GetForeground() == warnStyle.GetForeground() {
		t.Error("ok and warn must not use the same colour")
	}
	if okStyle.GetForeground() == errStyle.GetForeground() {
		t.Error("ok and err must not use the same colour")
	}
}

func TestNoScreenHasTrailingWhitespace(t *testing.T) {
	// Trailing runs of spaces are invisible until someone selects the text, and
	// they come for free from styling a multi-line string.
	m := netModel()
	screens := map[string]string{
		"list":    m.View(),
		"detail":  func() model { x := send(m, "enter"); return x }().View(),
		"proxy":   func() model { x := send(m, "p"); return x }().View(),
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
		"list":  m.View(),
		"proxy": send(m, "p").View(),
		"add":   send(m, "a").View(),
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
// stripANSI is stripStyles under the name the tests have always used. Kept as
// an alias rather than a second copy: the two drifting would mean tests
// asserting on text the interface never renders.
func stripANSI(s string) string { return stripStyles(s) }

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

func TestEveryAdvertisedKeyDoesSomething(t *testing.T) {
	// A help line is a promise. This one was once copied from another screen
	// whose handler was not, so it offered rotate and remove and did neither.
	m := testModel()
	m.cursor = rowOf(m, focusApp)
	// "a" opens a screen; the rest now ask in the footer without leaving it.
	if next := send(m, "a"); next.scr != screenAddForm {
		t.Error("'a' is advertised on the list but does nothing")
	}
	for _, k := range []string{"c", "r", "x"} {
		if next := send(m, k); next.prompt == nil {
			t.Errorf("%q is advertised on the list but asks nothing", k)
		}
	}
}

func TestConfigImageIsEditable(t *testing.T) {
	// The pin is the trust anchor, so a wrong value fails at deploy time with a
	// registry "not found" -- which reads like a build problem, not a setting.
	m := send(testModel(), "c")
	if m.prompt == nil || m.prompt.kind != promptInput {
		t.Fatal("'c' should open an input in the footer")
	}
	if m.scr != screenList {
		t.Errorf("editing a setting should not leave the list, got %v", m.scr)
	}
	// Pre-filled, and the row it came from is still visible above it.
	if m.prompt.typed != "ghcr.io/you/blog-config" {
		t.Errorf("the input should start from the current value, got %q", m.prompt.typed)
	}

	// A tag is the mistake worth catching, same as when adding.
	for _, r := range ":v1" {
		m = send(m, string(r))
	}
	m = send(m, "enter")
	if m.prompt == nil || !strings.Contains(m.prompt.problem, "tag") {
		t.Errorf("a tag should be rejected, got %+v", m.prompt)
	}
	// Backspacing the mistake away clears the complaint and lets it through.
	m = send(m, "backspace", "backspace", "backspace", "enter")
	if m.prompt != nil {
		t.Error("a valid value should be accepted")
	}
}

func TestUnchangedConfigImageDoesNothing(t *testing.T) {
	// Pressing enter without editing should not re-run setup on the server.
	m := send(testModel(), "c", "enter")
	if m.prompt != nil {
		t.Error("enter should close the question")
	}
	if m.scr != screenList {
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

// --- known_hosts -------------------------------------------------------------

func TestKnownHostsIsOneLinePerNamePerKey(t *testing.T) {
	// The ordinary shape of ~/.ssh/known_hosts. Comma-joining names into one
	// pattern matches identically and is legal, but nobody has that in their
	// file, so it reads as something unusual exactly when someone is deciding
	// whether to trust it.
	tgt := target{user: "root", host: "1.2.3.4", port: 22,
		aliases: []string{"ormos.dev"}}
	names := tgt.knownHostsNames()
	if len(names) != 2 || names[0] != "1.2.3.4" || names[1] != "ormos.dev" {
		t.Fatalf("names wrong: %v", names)
	}
	for _, n := range names {
		if strings.Contains(n, ",") {
			t.Errorf("%q comma-joins names; each should be its own line", n)
		}
	}
}

func TestKnownHostsDeduplicatesAndKeepsPort(t *testing.T) {
	tgt := target{user: "root", host: "h", port: 2222,
		aliases: []string{"h", "other"}}
	names := tgt.knownHostsNames()
	if len(names) != 2 {
		t.Fatalf("a repeated name should appear once, got %v", names)
	}
	for _, n := range names {
		// A non-default port is bracketed, per name, or nothing matches.
		if !strings.HasPrefix(n, "[") || !strings.HasSuffix(n, "]:2222") {
			t.Errorf("%q is not in the [host]:port form a non-default port needs", n)
		}
	}
}

func TestInventoryAttachesContainersToTheirApp(t *testing.T) {
	out := strings.Join([]string{
		"server\tready\tDocker version 26.1.3",
		"app\tblog\tkomizo-blog\t/srv/blog\ta1b2c3d\t2\tghcr.io/you/blog-config",
		"container\tblog\tweb\tblog-web-1\trunning\tUp 3 hours\t2026-07-27T09:00:00.123456789Z\t0001-01-01T00:00:00Z\t0\tghcr.io/you/blog-web:a1b2c3d",
		"container\tblog\tdb\tblog-db-1\texited\tExited (1) 2 minutes ago\t2026-07-27T08:00:00Z\t2026-07-27T09:30:00Z\t1\tghcr.io/you/blog-db:a1b2c3d",
		"route\tblog\tblog.example.com,www.blog.example.com\tblog-web",
		"app\tshop\tkomizo-shop\t/srv/shop\tnone\t0\tghcr.io/you/shop-config",
	}, "\n")

	apps, _, _, _, _ := parseInventory(out)
	if len(apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(apps))
	}
	if n := len(apps[0].containers); n != 2 {
		t.Fatalf("blog should have 2 containers, got %d", n)
	}
	if n := len(apps[1].containers); n != 0 {
		t.Errorf("shop has none deployed, got %d containers", n)
	}

	// A stopped container must be listed, not dropped. An absent row reads as
	// "no such service", which is a different problem with a different fix.
	db := apps[0].containers[1]
	if db.service != "db" || db.name != "blog-db-1" {
		t.Errorf("got service=%q name=%q, want db/blog-db-1", db.service, db.name)
	}
	if db.up() {
		t.Error("an exited container must not report as up")
	}
	if !strings.Contains(db.status, "Exited (1)") {
		t.Errorf("docker's own wording should survive, got %q", db.status)
	}
	if !apps[0].containers[0].up() {
		t.Error("a running container should report as up")
	}

	// A site block with two names is one route, not two, and both names reach
	// the same container.
	if n := len(apps[0].routes); n != 1 {
		t.Fatalf("expected 1 route record, got %d", n)
	}
	net := netRow{name: "edge", members: []netMember{
		{container: "blog-web-1", aliases: []string{"web", "blog-web"}},
	}}
	byContainer := apps[0].routesByContainer(net)
	got := byContainer["blog-web-1"]
	if len(got) != 2 || got[0] != "blog.example.com" || got[1] != "www.blog.example.com" {
		t.Errorf("both hostnames should land on the web container, got %q", got)
	}
	if len(byContainer["blog-db-1"]) != 0 {
		t.Error("the database publishes nothing and should carry no routes")
	}
}
func TestRoutesStayAttachedWhenAnAppIsStopped(t *testing.T) {
	// A stopped container leaves the shared network, so the alias lookup that
	// normally attaches routes finds nothing -- and the hostnames an app serves
	// are exactly what you want to see while deciding whether to start it.
	//
	// Without the fallback this produced a row per route saying "nothing
	// answers to this", which is both noise and, for a deliberately stopped
	// app, not even news.
	a := appRow{
		name:    "ormos",
		running: "0",
		containers: []containerRow{
			{app: "ormos", service: "web", name: "ormos-web-1", state: "exited"},
			{app: "ormos", service: "api", name: "ormos-api-1", state: "exited"},
		},
		routes: []routeRow{
			{app: "ormos", sites: "ormos.dev,www.ormos.dev", upstream: "ormos-web"},
			{app: "ormos", sites: "api.ormos.dev", upstream: "ormos-api"},
		},
	}
	// Nothing on the network at all: every container is down.
	byContainer := a.routesByContainer(netRow{name: "edge"})
	if got := byContainer["ormos-web-1"]; len(got) != 2 {
		t.Errorf("the web container should keep its two hostnames, got %q", got)
	}
	if got := byContainer["ormos-api-1"]; len(got) != 1 {
		t.Errorf("the api container should keep its hostname, got %q", got)
	}

	// A bare service name works too -- compose allows either form.
	a.routes = []routeRow{{app: "ormos", sites: "x.example.com", upstream: "web"}}
	if got := a.routesByContainer(netRow{}); len(got["ormos-web-1"]) != 1 {
		t.Errorf("a bare service name should match its container, got %q", got)
	}

	// An upstream naming nothing this app has matches nothing, rather than
	// being attached to whichever container happened to be first.
	a.routes = []routeRow{{app: "ormos", sites: "x.example.com", upstream: "somethingelse"}}
	if got := a.routesByContainer(netRow{}); len(got) != 0 {
		t.Errorf("an unrelated upstream should match nothing, got %+v", got)
	}
}

func TestListNestsContainersWithoutMovingTheCursor(t *testing.T) {
	m := testModel()
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 3 hours"},
		{app: "blog", service: "db", name: "blog-db-1", state: "exited", status: "Exited (1) 2 minutes ago"},
	}

	// With two containers between them, selecting the second app must still
	// land on shop -- the container rows are focusable now, so this is about
	// the view and the key handling agreeing on the same index.
	m.cursor = m.firstAppRow() + 3
	got := stripANSI(viewList(m))

	var selected string
	for _, ln := range strings.Split(got, "\n") {
		if strings.Contains(ln, "▍") {
			selected = ln
		}
	}
	if !strings.Contains(selected, "shop") {
		t.Errorf("cursor 1 should select the second APP, selected line was %q", selected)
	}

	for _, want := range []string{"web", "db"} {
		if !strings.Contains(got, want) {
			t.Errorf("list is missing %q:\n%s", want, got)
		}
	}
	// Children are nested under their parent and the block is closed off.
	if !strings.Contains(got, "├ web") || !strings.Contains(got, "└ db") {
		t.Errorf("containers should be nested, last one corner-joined:\n%s", got)
	}
	// The status dot leads every row that runs, app and container alike.
	if strings.Count(got, "●") < 2 {
		t.Errorf("each running row should carry a status dot:\n%s", got)
	}
}

func TestAddFormAlwaysAsksForOtherNames(t *testing.T) {
	// Host keys are pinned per name, so a name CI dials that is missing from
	// the value fails the deploy with "no entry for <name>". This was once
	// asked only when connected by IP, which silently excluded the case that
	// prompted the fix: an admin name for the box (komizo.example.com) that is
	// not the name CI deploys to (app.example.com).
	for _, host := range []string{"64.177.120.111", "komizo.example.com"} {
		f := newAddForm(target{user: "root", host: host, port: 22})
		if len(f.fields) != 3 {
			t.Fatalf("%s: expected the extra-names field, got %d fields", host, len(f.fields))
		}
		// Optional either way: most boxes are reached by one name.
		if err := f.fields[2].check(""); err != nil {
			t.Errorf("%s: the field must be optional, got %v", host, err)
		}
		if err := f.fields[2].check("not a hostname!"); err == nil {
			t.Errorf("%s: expected a bad hostname to be rejected", host)
		}
	}
}

func TestKnownAsSplitsAndTrims(t *testing.T) {
	f := newAddForm(target{user: "root", host: "komizo.example.com", port: 22})
	f.fields[2].value = " app.example.com ,, www.example.com,"
	got := f.knownAs()
	want := []string{"app.example.com", "www.example.com"}
	if len(got) != len(want) {
		t.Fatalf("knownAs() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("knownAs()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// A form left blank must not produce a phantom empty name, which would
	// emit a known_hosts line beginning with a space.
	f.fields[2].value = "  "
	if n := len(f.knownAs()); n != 0 {
		t.Errorf("blank field produced %d names, want 0", n)
	}
}

func TestAliasesSurviveOntoTheServerScreen(t *testing.T) {
	// The value shown by the server screen is built from the target, so an
	// alias given at add time has to be recorded there. Passing it only to the
	// add meant the screen meant to be the durable home for SSH_KNOWN_HOSTS
	// gave a shorter answer than the add had just printed.
	tgt := target{user: "root", host: "komizo.example.com", port: 22}
	tgt.aliases = mergeNames(tgt.aliases, []string{"app.example.com"})
	tgt.aliases = mergeNames(tgt.aliases, []string{"app.example.com", "shop.example.com"})

	names := tgt.knownHostsNames()
	want := []string{"komizo.example.com", "app.example.com", "shop.example.com"}
	if len(names) != len(want) {
		t.Fatalf("knownHostsNames() = %q, want %q", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("name %d = %q, want %q", i, names[i], want[i])
		}
	}

	// And the rendered value carries a line per name, which is what CI matches.
	keys := [][2]string{{"ssh-ed25519", "AAAAC3Nz"}}
	got := formatKnownHosts(tgt, keys)
	for _, n := range want {
		if !strings.Contains(got, n+" ssh-ed25519 AAAAC3Nz") {
			t.Errorf("known_hosts is missing a line for %q:\n%s", n, got)
		}
	}
}

func TestIsIPDistinguishesNamesFromAddresses(t *testing.T) {
	for _, c := range []struct {
		host string
		ip   bool
	}{
		{"64.177.120.111", true},
		{"::1", true},
		{"ormos.dev", false},
		{"1.2.3.4.example.com", false},
	} {
		if got := (target{host: c.host}).isIP(); got != c.ip {
			t.Errorf("isIP(%q) = %v, want %v", c.host, got, c.ip)
		}
	}
}

func TestRotationDoesNotOfferHostKeys(t *testing.T) {
	// Rotating replaces the deploy keypair. The server's own host keys do not
	// move, so presenting SSH_KNOWN_HOSTS as something to copy would say
	// something else needs updating in GitHub when nothing does.
	rot := addResult{app: "blog", keyPath: "/k", knownHosts: "h ssh-ed25519 AAAA",
		rotated: true, onClipboard: -1}
	v := rot.view()
	if strings.Contains(v, "variable, not a secret") {
		t.Error("a rotation should not present the host keys as a value to paste")
	}
	if !strings.Contains(v, "unchanged") {
		t.Error("it should say the host keys did not change")
	}
	if rot.items() != 1 {
		t.Errorf("a rotation has one copyable row, got %d", rot.items())
	}

	// A fresh setup still offers both.
	fresh := addResult{app: "blog", keyPath: "/k", knownHosts: "h ssh-ed25519 AAAA", onClipboard: -1}
	if fresh.items() != resultItems {
		t.Errorf("a fresh setup offers %d rows, got %d", resultItems, fresh.items())
	}
	if !strings.Contains(fresh.view(), "SSH_KNOWN_HOSTS") {
		t.Error("a fresh setup should still show the host keys")
	}
}

func TestListAccountsForKnownHosts(t *testing.T) {
	// The keys belong to the server, not an app: every app on the box pins the
	// same ones. Showing them only in the output of adding an app meant wanting
	// them again meant re-running setup.
	m := netModel()
	m.srv.hostKeys = [][2]string{
		{"ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAI"},
		{"ssh-rsa", "AAAAB3NzaC1yc2EAAAADAQABA"},
	}
	v := m.View()
	// Summarised, not printed: it is one line per name per key, and it sits
	// above the app list now. The value itself goes to the clipboard.
	if !strings.Contains(v, "known_hosts") {
		t.Error("the list should account for the value CI pins")
	}
	if !strings.Contains(v, "2 lines for box.example.com") {
		t.Errorf("it should say how many lines and which names:\n%s", v)
	}
	// The way to get it is on the row itself, so selecting it says so.
	m.cursor = rowOf(m, focusHosts)
	if !strings.Contains(m.View(), "copy SSH_KNOWN_HOSTS") {
		t.Error("selecting the row should offer to copy it")
	}
}

func TestKnownHostsFormattingIsSharedWithWhatIsCopied(t *testing.T) {
	// The screen and the clipboard must not drift: both go through
	// formatKnownHosts, so one format change cannot update only one of them.
	tgt := target{user: "root", host: "1.2.3.4", port: 22, aliases: []string{"ormos.dev"}}
	keys := [][2]string{{"ssh-ed25519", "AAAA"}}
	got := formatKnownHosts(tgt, keys)
	want := "1.2.3.4 ssh-ed25519 AAAA\normos.dev ssh-ed25519 AAAA"
	if got != want {
		t.Errorf("formatKnownHosts =\n%q\nwant\n%q", got, want)
	}
}

func TestHelpFollowsTheCursor(t *testing.T) {
	// Enter does the obvious thing to whatever is selected, which is only not a
	// guessing game if the hint changes with it.
	m := testModel()
	m.srv.hostKeys = [][2]string{{"ssh-ed25519", "AAAA"}}
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 3 hours"},
	}

	for _, c := range []struct {
		cursor int
		want   string
	}{
		{0, "update server"},        // the box
		{1, "copy SSH_KNOWN_HOSTS"}, // known_hosts
		{2, "stop"},                 // proxy, running
		{3, "stop"},                 // app, running
		{4, "stop"},                 // container, running
	} {
		m.cursor = c.cursor
		if got := m.enterLabel(); got != c.want {
			t.Errorf("cursor %d: enter is labelled %q, want %q", c.cursor, got, c.want)
		}
	}

	// And the log key names the container it would show.
	m.cursor = 4
	if !strings.Contains(m.View(), "web log") {
		t.Error("with a container selected, l should offer that container's log")
	}
	// An app has a log of its own -- every service interleaved -- rather than
	// falling back to something the cursor is not on.
	m.cursor = 3
	if !strings.Contains(m.View(), "blog log") {
		t.Error("with an app selected, l should offer that app's log")
	}
}

func TestEnterOnTheDockerRowUpdatesTheServer(t *testing.T) {
	// The action sits on the row showing the thing it changes: re-running setup
	// is what moves that version, so the version is where you press it. There
	// is no second way to reach it -- a global key as well would be two routes
	// to one action, and one of them undiscoverable from the row it affects.
	m := netModel()
	m.cursor = 0
	m = send(m, "enter")
	if m.prompt == nil {
		t.Fatal("enter on the docker row should ask about an update")
	}
	if !strings.Contains(m.prompt.detail, "Docker updates") {
		t.Errorf("the question should say what it does: %q", m.prompt.detail)
	}
	// It must be clear the apps are not touched, since that is the fear.
	if !strings.Contains(m.prompt.detail, "apps keep running") {
		t.Error("it should say the apps are unaffected")
	}
}

func TestStartStopRunsInlineWithoutConfirming(t *testing.T) {
	// Start and stop are reversible by pressing the same key again, so a prompt
	// in front of them is one people learn to dismiss without reading -- which
	// is worse than not having it. The feedback is the spinner on the row.
	m := netModel()
	m.cursor = rowOf(m, focusProxy)
	m = send(m, "enter") // asks first
	if m.prompt == nil {
		t.Fatal("start/stop should ask before acting")
	}
	m, cmd := sendCmd(m, "y")
	if m.scr != screenList {
		t.Fatalf("start/stop must not leave the list, got %v", m.scr)
	}
	if !m.busy[proxyContainer] {
		t.Error("the proxy row should be marked busy")
	}
	if cmd == nil {
		t.Error("it should actually run something")
	}
	// While busy the row shows a spinner instead of its status dot.
	if !strings.Contains(m.View(), "⠋") {
		t.Errorf("a busy row should show a spinner:\n%s", stripANSI(m.View()))
	}

	// A second attempt must not queue a second command.
	before := len(m.busy)
	m2 := send(m, "enter", "y")
	if len(m2.busy) != before {
		t.Error("acting again while in flight should do nothing")
	}

	// Finishing clears the spinner and refreshes rather than guessing.
	next, refresh := m.Update(opDoneMsg{key: proxyContainer})
	m = next.(model)
	if m.busy[proxyContainer] {
		t.Error("the row should stop spinning when the action finishes")
	}
	if refresh == nil {
		t.Error("it should re-read the box rather than assume the new state")
	}
}

func TestAFailedActionSurfacesWithoutAScreen(t *testing.T) {
	m := netModel()
	m.busy = map[string]bool{"app:blog": true}
	next, _ := m.Update(opDoneMsg{key: "app:blog", err: errStub("no such container")})
	m = next.(model)
	if m.busy["app:blog"] {
		t.Error("a failure must clear the busy marker too, or the row spins forever")
	}
	if !strings.Contains(m.View(), "no such container") {
		t.Error("the reason should be on the list, since there is no output screen")
	}
}

type errStub string

func (e errStub) Error() string { return string(e) }

func sendCmd(m model, k string) (model, tea.Cmd) {
	next, cmd := m.Update(key(k))
	return next.(model), cmd
}

func TestUpdateServerHasNoGlobalKey(t *testing.T) {
	// "u" was a second route to what enter on the docker row already does.
	m := testModel()
	m.cursor = rowOf(m, focusApp) // deliberately NOT the docker row
	if next := send(m, "u"); next.scr != screenList {
		t.Errorf("'u' should no longer do anything, got %v", next.scr)
	}
	if strings.Contains(m.View(), "update server") {
		t.Error("the help should not advertise a key that does nothing")
	}
}

func TestAppKeysOnlyOfferedWithAnAppSelected(t *testing.T) {
	// Offering "rotate key" with the cursor on the Docker version offers it for
	// nothing: there is no app for it to apply to, so the hint is a small lie.
	m := testModel()

	m.cursor = rowOf(m, focusServer)
	v := stripANSI(m.View())
	for _, k := range []string{"rotate key", "remove", "config image"} {
		if strings.Contains(v, k) {
			t.Errorf("%q should not be offered with no app selected:\n%s", k, v)
		}
	}
	// And pressing them does nothing rather than acting on some other app.
	for _, k := range []string{"c", "r", "x"} {
		if next := send(m, k); next.scr != screenList {
			t.Errorf("%q with no app selected should do nothing, got %v", k, next.scr)
		}
	}
	// "a" is the exception: it creates an app rather than acting on one, so it
	// works from anywhere and lives on the always-available line.
	if next := send(m, "a"); next.scr != screenAddForm {
		t.Errorf("'a' should work with no app selected, got %v", next.scr)
	}

	m.cursor = rowOf(m, focusApp)
	v = stripANSI(m.View())
	for _, k := range []string{"rotate key", "remove", "config image"} {
		if !strings.Contains(v, k) {
			t.Errorf("%q should be offered with an app selected:\n%s", k, v)
		}
	}

	// A container row does NOT count. The keys are app-wide, so offering them
	// next to one container's name would say something untrue.
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running"},
	}
	m.cursor = rowOf(m, focusContainer)
	cv := stripANSI(m.View())
	for _, gone := range []string{"rotate key", "remove", "config image"} {
		if strings.Contains(cv, gone) {
			t.Errorf("%q must not be offered on a container row:\n%s", gone, cv)
		}
	}
	for _, k := range []string{"c", "r", "x"} {
		if next := send(m, k); next.scr != screenList {
			t.Errorf("%q on a container row should do nothing, got %v", k, next.scr)
		}
	}
}

func TestAddIsStillReachableOnAnEmptyBox(t *testing.T) {
	// The gate must not lock the only thing there is to do on a fresh server.
	m := testModel()
	m.apps = nil
	m.cursor = 0
	if !strings.Contains(stripANSI(m.View()), "add an app") {
		t.Error("a box with no apps must still offer to add one")
	}
	if next := send(m, "a"); next.scr != screenAddForm {
		t.Errorf("'a' should open the add form on an empty box, got %v", next.scr)
	}
}

func TestHelpSplitsGlobalFromContextual(t *testing.T) {
	// Two lines: what is always true, then what is true of the selected row.
	// One line meant the two keys that always work were no easier to find than
	// the four that only work on an app.
	m := testModel()
	m.srv.hostKeys = [][2]string{{"ssh-ed25519", "AAAA"}}

	for _, k := range []focusKind{focusServer, focusHosts, focusProxy, focusApp} {
		m.cursor = rowOf(m, k)
		v := stripANSI(m.View())
		for _, always := range []string{"refresh", "quit", "select"} {
			if !strings.Contains(v, always) {
				t.Errorf("%v: %q must be offered from every row", k, always)
			}
		}
	}

	// The app keys are absent from rows they cannot act on.
	m.cursor = rowOf(m, focusHosts)
	for _, gone := range []string{"rotate key", "remove", "config image", "reinstall"} {
		if strings.Contains(stripANSI(m.View()), gone) {
			t.Errorf("%q should not be offered on the known_hosts row", gone)
		}
	}
	// And present on one they can.
	m.cursor = rowOf(m, focusApp)
	if !strings.Contains(stripANSI(m.View()), "rotate key") {
		t.Error("the app row should offer the app keys")
	}
}

func TestAbsentThingsStayReachable(t *testing.T) {
	// An app and a proxy that do not exist have no row to select, so the keys
	// that create them are offered wherever the cursor is until they do.
	m := testModel()
	m.apps = nil
	m.proxy = proxyRow{}
	m.cursor = 0
	v := stripANSI(m.View())
	if !strings.Contains(v, "add an app") {
		t.Error("a box with no apps must offer to add one from anywhere")
	}
	if !strings.Contains(v, "install a proxy") {
		t.Error("a box with no proxy must offer to install one from anywhere")
	}
}

func TestAddIsGlobalButTheDestructiveKeysAreNot(t *testing.T) {
	// Adding creates an app rather than acting on one, and is done often, so it
	// is always available. Remove and rotate act on a selection, and offering
	// them without one invites the question "remove what?".
	m := testModel()
	m.srv.hostKeys = [][2]string{{"ssh-ed25519", "AAAA"}}

	for _, k := range []focusKind{focusServer, focusHosts, focusProxy} {
		m.cursor = rowOf(m, k)
		v := stripANSI(m.View())
		if !strings.Contains(v, "add an app") {
			t.Errorf("%v: add should be offered from every row", k)
		}
		for _, gone := range []string{"remove", "rotate key", "config image"} {
			if strings.Contains(v, gone) {
				t.Errorf("%v: %q must not be offered with no app selected", k, gone)
			}
		}
		if next := send(m, "x"); next.scr != screenList {
			t.Errorf("%v: 'x' must do nothing with no app selected", k)
		}
		if next := send(m, "r"); next.scr != screenList {
			t.Errorf("%v: 'r' must do nothing with no app selected", k)
		}
	}
}
func TestTheProxySectionIsPlainRows(t *testing.T) {
	// Same shape as the Server section above it: a heading, then label/value
	// rows. The image lived in the heading for a while, which made this the one
	// section on the page with a different anatomy.
	m := netModel()
	v := stripANSI(m.View())
	if !strings.Contains(v, "Proxy\n") {
		t.Errorf("the heading should be the word alone:\n%s", v)
	}
	for _, want := range []string{"status", "image", "network"} {
		found := false
		for _, ln := range strings.Split(v, "\n") {
			if strings.HasPrefix(strings.TrimSpace(ln), want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the proxy section is missing a %q row:\n%s", want, v)
		}
	}
	if !strings.Contains(v, "caddy:2") {
		t.Error("the image should still be shown, on its own row")
	}

	// A box with no proxy has no image, and says so rather than showing blank.
	m.proxy = proxyRow{}
	if !strings.Contains(stripANSI(m.View()), "not installed") {
		t.Error("with no proxy the status row should say so")
	}
}

func TestTheHostIsNamedWhereItMatters(t *testing.T) {
	// The address moved out of the header, which used to put it on every
	// screen. Anything destructive has to name the box itself now, or the most
	// dangerous prompt in the program says "this server" and means nothing.
	m := testModel()
	if strings.Contains(stripANSI(header()), "@") {
		t.Error("the header should no longer carry the address")
	}
	if !strings.Contains(stripANSI(m.View()), "root@box.example.com") {
		t.Error("the Server section should carry it instead")
	}

	m.cursor = rowOf(m, focusApp)
	if q := send(m, "x").prompt; q == nil || !strings.Contains(q.question, "box.example.com") {
		t.Error("the remove question must name the host")
	}
}

func TestAddressShowsANonDefaultPort(t *testing.T) {
	// Port 22 is the one everybody assumes; anything else is worth reading.
	if got := (target{user: "root", host: "box", port: 22}).display(); got != "root@box" {
		t.Errorf("port 22 should stay implicit, got %q", got)
	}
	if got := (target{user: "root", host: "box", port: 2222}).display(); got != "root@box:2222" {
		t.Errorf("a non-default port should be shown, got %q", got)
	}
}

func TestAQuestionTakesTheKeysWhileItIsOpen(t *testing.T) {
	// Typing an app's name to confirm its removal must not also be pressing the
	// keys that act on it -- "x" is in "blog" only by luck, but "a" is in
	// plenty of app names, and it would otherwise open the add form mid-answer.
	m := testModel()
	m.cursor = rowOf(m, focusApp)
	m = send(m, "x")

	before := m.cursor
	m = send(m, "a", "down", "up")
	if m.scr != screenList {
		t.Errorf("keys must not reach the list while a question is open, got %v", m.scr)
	}
	if m.cursor != before {
		t.Error("arrow keys must not move the cursor out from under the question")
	}
	if m.prompt == nil || m.prompt.typed != "a" {
		t.Errorf("the letters should have gone into the answer, got %+v", m.prompt)
	}

	// Esc always abandons it, leaving everything as it was.
	m = send(m, "esc")
	if m.prompt != nil {
		t.Error("esc should close the question")
	}
	if m.scr != screenList {
		t.Error("and leave the list exactly where it was")
	}
}

func TestQuestionsNeverLeaveTheList(t *testing.T) {
	// The whole point: the row you are deciding about stays on screen.
	m := testModel()
	m.cursor = rowOf(m, focusApp)
	for _, k := range []string{"c", "r", "x", "p"} {
		next := send(m, k)
		if next.scr != screenList {
			t.Errorf("%q left the list for %v", k, next.scr)
		}
		if next.prompt == nil {
			t.Errorf("%q asked nothing", k)
		}
		if !strings.Contains(stripANSI(next.View()), "ghcr.io/you/blog-config") {
			t.Errorf("%q hid the list behind the question", k)
		}
	}
	// And the server row's question behaves the same.
	m.cursor = rowOf(m, focusServer)
	if next := send(m, "enter"); next.scr != screenList || next.prompt == nil {
		t.Error("updating the server should ask in the footer too")
	}
}

func TestTheFooterIsPinnedAndRuledOff(t *testing.T) {
	m := testModel()
	m.apps = m.apps[:1]
	m.width, m.height = 70, 34

	v := stripANSI(m.View())
	lines := strings.Split(v, "\n")
	if got := len(lines); got > m.height {
		t.Errorf("rendered %d lines into a %d-line terminal", got, m.height)
	}
	// The last non-blank line is the key hints, not the end of the app list.
	last := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			last = lines[i]
			break
		}
	}
	if !strings.Contains(last, "rotate key") && !strings.Contains(last, "quit") {
		t.Errorf("the footer should be the last thing on screen, got %q", last)
	}
	// Exactly one rule, above the footer. The title needs no underline; there
	// was never any danger of confusing it with the content.
	if n := strings.Count(v, strings.Repeat("─", ruleWidth(m.width))); n != 1 {
		t.Errorf("expected one rule, above the footer, got %d", n)
	}

	// A page that already overflows must not be padded further -- scrolling the
	// top away to pin the bottom trades position for the content itself.
	m.height = 12
	if n := strings.Count(stripANSI(m.View()), "\n"); n < 12 {
		t.Error("an overflowing page should render in full, not be truncated")
	}
}

func TestStartStopAsksFirst(t *testing.T) {
	m := testModel()
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 2 days"},
	}

	for _, k := range []focusKind{focusProxy, focusApp, focusContainer} {
		m.cursor = rowOf(m, k)
		next := send(m, "enter")
		if next.prompt == nil {
			t.Fatalf("%v: enter should ask before starting or stopping", k)
		}
		if next.prompt.kind != promptConfirm {
			t.Errorf("%v: it is reversible, so y/n is enough", k)
		}
		if len(next.busy) != 0 {
			t.Errorf("%v: nothing should run until the question is answered", k)
		}
		// And "y" carries it out.
		if done := send(next, "y"); len(done.busy) != 1 {
			t.Errorf("%v: y should start the action", k)
		}
	}

	// Stopping something that serves traffic names what goes quiet -- the fact
	// that makes the answer obvious and the one the row does not show.
	m.cursor = rowOf(m, focusApp)
	if q := send(m, "enter").prompt; !strings.Contains(q.detail, "blog.example.com") {
		t.Errorf("the question should name the hostnames that stop answering: %q", q.detail)
	}
}

func TestEverySectionIsAHeading(t *testing.T) {
	// One page, three groups. The title is the only coloured thing on it; the
	// headings are bold, so they mark a break without competing with it.
	v := stripANSI(testModel().View())
	for _, want := range []string{"komizo", "Server", "Proxy", "Apps"} {
		if !strings.Contains(v, want) {
			t.Errorf("the page is missing the %q heading", want)
		}
	}
	// Order matters: the box, then the thing every app depends on, then them.
	iS, iP, iA := strings.Index(v, "Server"), strings.Index(v, "Proxy"), strings.Index(v, "Apps")
	if !(iS < iP && iP < iA) {
		t.Errorf("sections out of order: Server=%d Proxy=%d Apps=%d", iS, iP, iA)
	}
}

func TestAppAndContainerColumnsShareTheirWidths(t *testing.T) {
	// One set of columns, not two. A table whose second column starts in two
	// different places is one your eye has to re-find on every row.
	m := testModel()
	m.apps = m.apps[:1]
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 2 days"},
	}
	var appLine, ctrLine string
	for _, ln := range strings.Split(stripANSI(m.View()), "\n") {
		switch {
		case strings.Contains(ln, "blog-config"):
			appLine = ln
		case strings.Contains(ln, "├") || strings.Contains(ln, "└"):
			ctrLine = ln
		}
	}
	if appLine == "" || ctrLine == "" {
		t.Fatal("expected both an app row and a container row")
	}
	// The status dot starts at the same COLUMN on both -- counted in runes, not
	// bytes: the cursor bar is three bytes and one column, which is exactly the
	// confusion this whole layout exists to avoid.
	col := func(s string) int {
		for i, r := range []rune(s) {
			if r == '●' || r == '○' || r == '◐' {
				return i
			}
		}
		return -1
	}
	if a, c := col(appLine), col(ctrLine); a != c || a < 0 {
		t.Errorf("dots do not line up: app at %d, container at %d\n%s\n%s", a, c, appLine, ctrLine)
	}
}

func TestTheCursorBarStaysInOneColumn(t *testing.T) {
	// It used to step two columns right the moment the selection reached the
	// app list, because the table nested its rows further in than the label
	// rows above it. A cursor that moves sideways as it moves down is a cursor
	// you have to track.
	m := testModel()
	m.srv.hostKeys = [][2]string{{"ssh-ed25519", "AAAA"}}
	m.apps = m.apps[:1]
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 2 days"},
	}

	seen := map[int]bool{}
	for i := range m.focusItems() {
		m.cursor = i
		for _, ln := range strings.Split(stripANSI(m.View()), "\n") {
			if col := strings.IndexRune(ln, '▍'); col >= 0 {
				seen[len([]rune(ln[:col]))] = true
			}
		}
	}
	if len(seen) != 1 {
		t.Errorf("the cursor bar appeared in %d different columns: %v", len(seen), seen)
	}
	if !seen[0] {
		t.Errorf("the bar should sit in the first column, got %v", seen)
	}
}

func TestTheSpinnerHoldsUntilTheNewStateArrives(t *testing.T) {
	// The bug this exists for: the command returns, the row goes idle, and for
	// one frame it shows the state it was in BEFORE the command -- so stopping
	// something read green -> spinner -> green -> red.
	m := netModel()
	m.apps = []appRow{{
		name: "blog", dir: "/srv/blog", running: "1",
		containers: []containerRow{
			{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 2 days"},
		},
	}}
	m.cursor = rowOf(m, focusContainer)
	m = send(m, "enter", "y")
	if !m.busy["blog-web-1"] {
		t.Fatal("the row should be busy once the action starts")
	}

	// Command done -- but the model still holds the pre-command state, so the
	// row must keep spinning rather than briefly claim to be running.
	next, cmd := m.Update(opDoneMsg{key: "blog-web-1"})
	m = next.(model)
	if m.busy["blog-web-1"] {
		t.Error("the command is no longer in flight")
	}
	if !m.settling["blog-web-1"] {
		t.Error("the row should still be spinning, waiting for the refresh")
	}
	if cmd == nil {
		t.Fatal("it should re-read the box rather than guess")
	}
	if !strings.Contains(stripANSI(m.View()), "⠋") {
		t.Error("a settling row still shows a spinner")
	}

	// The refresh lands, carrying the real new state, and the spinner stops.
	next, _ = m.Update(appsMsg{
		srv:   serverRow{state: "ready"},
		proxy: m.proxy,
		apps: []appRow{{
			name: "blog", dir: "/srv/blog", running: "0",
			containers: []containerRow{
				{app: "blog", service: "web", name: "blog-web-1", state: "exited"},
			},
		}},
	})
	m = next.(model)
	if m.spinning() {
		t.Error("once the new state is in, nothing should still be spinning")
	}
	// The dot carries the state; the row shows how long it has been in it.
	if m.apps[0].containers[0].up() {
		t.Error("and the row should show the state it actually ended in")
	}
}

func TestOneTickerHoweverManyRowsAreMoving(t *testing.T) {
	// Two tickers animate the spinner at double speed.
	m := netModel()
	m.busy = map[string]bool{"app:blog": true}
	if !m.spinning() {
		t.Fatal("a busy row is spinning")
	}
	before := m.spin
	next, _ := m.Update(spinMsg{})
	if next.(model).spin != before+1 {
		t.Error("a tick should advance the frame exactly once")
	}
	// And with nothing moving, the ticker is allowed to die.
	m.busy, m.settling = nil, nil
	if _, cmd := m.Update(spinMsg{}); cmd != nil {
		t.Error("an idle page should not keep scheduling ticks")
	}
}

func TestStrippingStylesLeavesTheText(t *testing.T) {
	// brighten works by removing what a value already carries and re-applying
	// one style, so the stripping has to be exact -- a stray escape byte would
	// show up as garbage in the middle of the selected row.
	in := okStyle.Render("●") + " running " + dimStyle.Render("Up 3 hours")
	if got := stripStyles(in); got != "● running Up 3 hours" {
		t.Errorf("stripStyles = %q", got)
	}
	if got := stripStyles("plain"); got != "plain" {
		t.Errorf("plain text should survive untouched, got %q", got)
	}
}
func TestEveryStatusIsTheSameCircle(t *testing.T) {
	// One shape, three colours. The shape used to vary too, which drew the eye
	// to the part carrying no information.
	for _, state := range []string{"ok", "warn", "err"} {
		if got := stripStyles(dot(state)); got != "●" {
			t.Errorf("dot(%q) = %q, want a filled circle", state, got)
		}
	}
	// Absence keeps its own mark: no proxy installed is not a status the proxy
	// is in.
	if got := stripStyles(dot("")); got == "●" {
		t.Error("the absent state should not look like a status")
	}
}

func TestSelectionKeepsTheGlyphAndBrightensTheRest(t *testing.T) {
	// Colour cannot be recovered from stripped text, so the glyph is kept out
	// of the brightening rather than restored afterwards. If that ever stops
	// being true, a red row would come back green when you select it.
	rows := []treeRow{
		{idx: 0, cells: []string{dot("err"), dimStyle.Render("blog"), dimStyle.Render("stopped")}},
	}
	out := tree(rows, 0)
	if !strings.Contains(stripStyles(out), "blog") || !strings.Contains(stripStyles(out), "stopped") {
		t.Errorf("the row lost its text: %q", stripStyles(out))
	}
	// The glyph survives verbatim, colour and all.
	if !strings.Contains(out, dot("err")) {
		t.Error("the status glyph should pass through selection untouched")
	}

	// And brighten itself never sees a glyph -- it strips unconditionally.
	if got := stripStyles(brighten(dimStyle.Render("x"))); got != "x" {
		t.Errorf("brighten mangled its input: %q", got)
	}
}

func TestARowWithNoStatusHasNoGlyphColumn(t *testing.T) {
	// A blank where a glyph would go pushes the value one column right of every
	// other value on the page, which is worse than not having the column.
	withGlyph := stripStyles(kvDot("status", dot("ok"), "running", false))
	without := stripStyles(kvDot("address", "", "root@box", false))
	if strings.Contains(without, "  root@box") && !strings.Contains(withGlyph, "  ●") {
		t.Errorf("values should start in the same column:\n%q\n%q", withGlyph, without)
	}
	if strings.Contains(without, " root@box") != true {
		t.Errorf("unexpected spacing: %q", without)
	}
}

func TestAQuestionIsNotAStatus(t *testing.T) {
	// Prompts used to lead with a status dot and colour the question amber,
	// which made every one of them read as a warning -- including "Config image
	// for blog", which is a setting. The footer is already fenced off by a rule
	// and is the only interactive part of the page.
	m := testModel()
	m.cursor = rowOf(m, focusApp)
	for _, k := range []string{"enter", "r", "x", "c"} {
		v := stripANSI(send(m, k).View())
		i := strings.LastIndex(v, "─")
		footer := v[i:]
		// "·" is the help line's separator, so only the status circle counts.
		if strings.Contains(footer, "●") {
			t.Errorf("%q: the question should carry no status glyph:\n%s", k, footer)
		}
		// And the question sits at the same indent as everything else, not one
		// column in from where a glyph used to be.
		for _, ln := range strings.Split(footer, "\n") {
			if strings.TrimSpace(ln) == "" {
				continue
			}
			if strings.HasPrefix(ln, "    ") {
				t.Errorf("%q: nothing in the footer should be double-indented: %q", k, ln)
			}
		}
	}
}

func TestOneDurationFormatEverywhere(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		ago  time.Duration
		want string
	}{
		{11 * time.Second, "now"},
		{59 * time.Second, "now"},
		{4 * time.Minute, "4m"},
		{59 * time.Minute, "59m"},
		{3*time.Hour + 12*time.Minute, "3h 12m"},
		{5 * time.Hour, "5h"},
		{36*time.Hour + 4*time.Minute, "1d 12h 4m"},
		{24*time.Hour + 5*time.Minute, "1d 5m"},
		{6*24*time.Hour + 2*time.Hour, "6d 2h"},
		{9 * 24 * time.Hour, "9d"},
	} {
		if got := since(now.Add(-c.ago)); got != c.want {
			t.Errorf("since(%s ago) = %q, want %q", c.ago, got, c.want)
		}
	}
	// Nothing to measure from.
	if got := since(time.Time{}); got != "—" {
		t.Errorf("a zero time should read as absent, got %q", got)
	}
	// A clock ahead of ours is not worth reporting as a negative age.
	if got := since(now.Add(time.Minute)); got != "now" {
		t.Errorf("a future timestamp should read as now, got %q", got)
	}
}

func TestEveryStateReadsTheSameWay(t *testing.T) {
	// Every state reads as a bare duration: the dot beside it says WHICH state,
	// so repeating that in text left the column holding two things -- one of
	// them redundant -- at three different widths depending on the word.
	now := time.Now()
	for _, c := range []struct {
		in   containerRow
		want string
	}{
		{containerRow{state: "running", startedAt: now.Add(-90 * time.Minute)}, "1h 30m"},
		{containerRow{state: "exited", finishedAt: now.Add(-5 * time.Minute)}, "5m"},
		{containerRow{state: "restarting", startedAt: now.Add(-20 * time.Second)}, "now"},
		// The exit code is the one fact neither the dot nor the duration
		// carries, and the first thing worth knowing when something stopped on
		// its own. A clean exit says nothing extra.
		{containerRow{state: "exited", exitCode: 1, finishedAt: now.Add(-5 * time.Minute)}, "5m  exit 1"},
	} {
		if got := c.in.stateText(); got != c.want {
			t.Errorf("stateText = %q, want %q", got, c.want)
		}
	}
}

func TestAnAppIsUpSinceItsLatestContainer(t *testing.T) {
	// The latest, not the earliest: an app with one container restarted a
	// minute ago has been serving completely for a minute, whatever the others
	// have been doing for a week -- and that minute is when whatever went wrong
	// went wrong.
	old := time.Now().Add(-7 * 24 * time.Hour)
	recent := time.Now().Add(-90 * time.Second)
	a := appRow{
		name: "blog", running: "2",
		containers: []containerRow{
			{app: "blog", state: "running", startedAt: old},
			{app: "blog", state: "running", startedAt: recent},
		},
	}
	if got := a.upSince(); !got.Equal(recent) {
		t.Errorf("upSince = %v, want the most recent start %v", got, recent)
	}

	// A stopped container does not count, however recently it ran.
	a.containers[1].state = "exited"
	if got := a.upSince(); !got.Equal(old) {
		t.Error("a stopped container should not set the app's uptime")
	}

	// Nothing running at all.
	a.containers[0].state = "exited"
	if !a.upSince().IsZero() {
		t.Error("an app with nothing running has no uptime")
	}
}

func TestTheClockRunsWithoutTouchingTheServer(t *testing.T) {
	// Durations are computed from timestamps the box already gave us, so
	// keeping them current is a repaint rather than a poll. The tick carries no
	// data and changes no state -- returning at all is the point.
	m := netModel()
	before := m
	next, cmd := m.Update(clockMsg{})
	if cmd == nil {
		t.Fatal("the clock should keep ticking")
	}
	after := next.(model)
	if after.cursor != before.cursor || after.scr != before.scr || len(after.apps) != len(before.apps) {
		t.Error("a tick must not change anything but the frame")
	}

	// And the rendered duration actually moves with the clock.
	m.apps = []appRow{{
		name: "blog", running: "1",
		containers: []containerRow{
			{app: "blog", service: "web", name: "blog-web-1", state: "running",
				startedAt: time.Now().Add(-90 * time.Second)},
		},
	}}
	first := stripANSI(m.View())
	m.apps[0].containers[0].startedAt = time.Now().Add(-150 * time.Second)
	if second := stripANSI(m.View()); first == second {
		t.Error("the view should re-read the clock on every render")
	}
}

func TestAnAppShowsItsDowntimeToo(t *testing.T) {
	// Containers show how long they have been stopped, so an app that shows
	// nothing while stopped is the one row that goes blank exactly when you are
	// looking at it.
	now := time.Now()
	a := appRow{
		name: "ormos", running: "0",
		containers: []containerRow{
			{app: "ormos", state: "exited", startedAt: now.Add(-9 * time.Hour), finishedAt: now.Add(-90 * time.Second)},
			{app: "ormos", state: "exited", startedAt: now.Add(-9 * time.Hour), finishedAt: now.Add(-2 * time.Minute)},
		},
	}
	// Down since the LAST one stopped -- an app is not down because one
	// container exited, it is down once the final one has.
	if got := a.stateText(); got != "1m" {
		t.Errorf("a stopped app should count from its last container stopping, got %q", got)
	}

	// Start one and it counts up from there instead.
	a.containers[0].state = "running"
	a.containers[0].startedAt = now.Add(-30 * time.Second)
	a.running = "1"
	if got := a.stateText(); got != "now" {
		t.Errorf("a running app should count from its latest start, got %q", got)
	}

	// An app with no containers has neither.
	if got := (appRow{name: "x"}).stateText(); got != "—" {
		t.Errorf("an app with no containers should show nothing, got %q", got)
	}
}

func TestTheLogWindowNeverOutgrowsTheTerminal(t *testing.T) {
	// The chrome around the log was a constant, and it was two lines short --
	// so a full window rendered taller than the terminal, the terminal
	// scrolled, and the title went off the top. A title that disappears once
	// there is something to read is the opposite of a title.
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, "a log line")
	}
	// Below about fifteen lines the chrome alone fills the terminal and there
	// is nothing sensible to do; this is the range a person would use.
	for _, h := range []int{16, 18, 24, 40, 60} {
		for _, loaded := range []bool{false, true} {
			m := netModel()
			m.width, m.height = 92, h
			m.scr, m.logsOf, m.logsLabel = screenLogs, "x-1", "x"
			if loaded {
				next, _ := m.Update(logsMsg{container: "x-1", lines: strings.Join(lines, "\n")})
				m = next.(model)
			}
			v := stripANSI(m.View())
			if n := strings.Count(v, "\n") + 1; n > h {
				t.Errorf("height=%d loaded=%v rendered %d lines", h, loaded, n)
			}
			// And the title is still the first thing on it.
			if got := strings.SplitN(v, "\n", 3)[1]; !strings.Contains(got, "komizo") {
				t.Errorf("height=%d loaded=%v: first line is %q", h, loaded, got)
			}
		}
	}
}

func TestALoadingLogSpinsInTheMiddle(t *testing.T) {
	m := netModel()
	m.width, m.height = 92, 24
	m.cursor = rowOf(m, focusProxy)
	m, _ = sendCmd(m, "l")
	if !m.loading() {
		t.Fatal("a log that has not arrived is loading")
	}
	if !m.spinning() {
		t.Error("the spinner ticker should be running while it loads")
	}
	if !strings.Contains(stripANSI(m.View()), spinFrames[0]) {
		t.Error("a loading log should show a spinner")
	}

	// A container that has genuinely logged nothing is NOT loading -- inferring
	// it from an empty body would spin forever waiting for what already came.
	next, _ := m.Update(logsMsg{container: proxyContainer, lines: ""})
	m = next.(model)
	if m.loading() {
		t.Error("an empty log has still arrived")
	}
	if !strings.Contains(stripANSI(m.View()), "logged nothing") {
		t.Error("it should say so rather than spinning")
	}
}

func TestStaticRoutesAppearWithoutPretendingToRun(t *testing.T) {
	// A hostname served off disk has no container, so it has no state and no
	// uptime -- but it does have a row. Without one, a hostname that works
	// looks exactly like a hostname nothing serves.
	m := testModel()
	m.apps = []appRow{{
		name: "ormos", dir: "/srv/ormos", running: "1",
		containers: []containerRow{
			{app: "ormos", service: "api", name: "ormos-api-1", state: "running",
				startedAt: time.Now().Add(-time.Hour)},
		},
		statics: []staticRow{
			{app: "ormos", sites: "ormos.dev,www.ormos.dev", root: "/srv/ormos/public/www"},
		},
	}}
	v := stripANSI(m.View())

	var line string
	for _, ln := range strings.Split(v, "\n") {
		if strings.Contains(ln, "ormos.dev") && strings.Contains(ln, "www") {
			line = ln
		}
	}
	if line == "" {
		t.Fatalf("the static route should have a row:\n%s", v)
	}
	// Named for its document root, and marked as what it is.
	if !strings.Contains(line, "www") || !strings.Contains(line, "static") {
		t.Errorf("row should name the root and say it is static: %q", line)
	}
	// No status dot: there is no process for it to describe, and a green one
	// would claim something is running.
	if strings.Contains(line, "●") {
		t.Errorf("a static row must not carry a status dot: %q", line)
	}

	// Not selectable either -- there is nothing to start, stop or read a log
	// from, so stopping on it would mean pressing down twice for nothing.
	before := len(m.focusItems())
	m.apps[0].statics = append(m.apps[0].statics,
		staticRow{app: "ormos", sites: "app.ormos.dev", root: "/srv/ormos/public/app"})
	if after := len(m.focusItems()); after != before {
		t.Errorf("static rows should not be focusable: %d -> %d", before, after)
	}
}

func TestStaticHostnamesCountAsRoutes(t *testing.T) {
	// They are published, and just as gone when the app is removed -- so they
	// belong in the list of what an app serves, wherever that list is used.
	a := appRow{
		name:    "ormos",
		routes:  []routeRow{{app: "ormos", sites: "api.ormos.dev", upstream: "ormos-api"}},
		statics: []staticRow{{app: "ormos", sites: "ormos.dev,www.ormos.dev", root: "/srv/ormos/public/www"}},
	}
	got := a.allRoutes()
	if len(got) != 3 {
		t.Fatalf("allRoutes() = %q, want all three hostnames", got)
	}
}

func TestAStaticRootIsNamedForItsLastSegment(t *testing.T) {
	for _, c := range []struct{ root, want string }{
		{"/srv/ormos/public/www", "www"},
		{"/srv/ormos/public/app/", "app"},
		{"/srv/site/public", "public"},
		{"public", "public"},
	} {
		if got := (staticRow{root: c.root}).label(); got != c.want {
			t.Errorf("label(%q) = %q, want %q", c.root, got, c.want)
		}
	}
}

func TestTheImageColumnDropsTheVersionItRepeats(t *testing.T) {
	// Every service is pinned to ${APP_VERSION}, so the tag is the commit SHA
	// already shown on the app's row -- sixty characters of column saying what
	// the row above said.
	c := containerRow{image: "ghcr.io/you/blog-api:a1b2c3d4e5f6"}
	if got := c.imageText("a1b2c3d4e5f6"); got != "ghcr.io/you/blog-api" {
		t.Errorf("imageText = %q, want the repo alone", got)
	}
	// A tag that is NOT the version is the interesting case: a service left on
	// :latest, or an upstream image. Shown in full.
	if got := c.imageText("deadbeef"); got != "ghcr.io/you/blog-api:a1b2c3d4e5f6" {
		t.Errorf("a tag that is not the version should survive, got %q", got)
	}
	if got := (containerRow{image: "caddy:2"}).imageText("a1b2c3d"); got != "caddy:2" {
		t.Errorf("an upstream image should be shown as it is, got %q", got)
	}
	// An app that has never deployed has no version to compare against.
	if got := c.imageText("none"); got != "ghcr.io/you/blog-api:a1b2c3d4e5f6" {
		t.Errorf("with no version the image is shown whole, got %q", got)
	}
}
