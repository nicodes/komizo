package app

import (
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func testModel() model {
	m := newModel(target{user: "root", host: "box.example.com", port: 22})
	m.width, m.height = 100, 40
	m.scr = screenIndex
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
		{container: "komizo-proxy", aliases: []string{"komizo-proxy"}},
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
	case "shift+up":
		return tea.KeyMsg{Type: tea.KeyShiftUp}
	case "shift+down":
		return tea.KeyMsg{Type: tea.KeyShiftDown}
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

// showResult puts an operation's values in the footer, the way finishing one
// does. There is no result SCREEN to put the model on any more.
func showResult(m model, r *addResult) model {
	m.run = newRunState("Setting up " + r.app)
	m.run.done, m.run.result = true, r
	m.prompt = &prompt{kind: promptResult}
	return m
}

// openAddForm selects the row under the app list and presses enter, which is
// the only way in now that adding has no key of its own. The form opens in the
// footer -- the screen stays on the list.
func openAddForm(m model) model {
	m.cursor = rowOf(m, focusAdd)
	return send(m, "enter")
}

func TestEmptyListExplainsWhatAnAppIs(t *testing.T) {
	m := testModel()
	m.apps = nil
	m.cursor = 0
	v := m.View()
	if !strings.Contains(v, "compose stack") {
		t.Error("empty list should say what an app is")
	}
	// The row that adds one is the only thing to select on a box with none.
	if !strings.Contains(v, "add an app") {
		t.Error("empty list should offer the row that adds one")
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
	// Page order: the komizo server row (os and komizo cli are pure facts, not
	// focusable), then the proxy and its TLS gate, then the apps. The cursor is an
	// index into this list, so the two have to agree.
	want := []focusKind{focusKomizo, focusProxy, focusGate, focusApp, focusContainer, focusApp, focusAdd}
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
	// Found by kind rather than by a hardcoded index: the box rows above these
	// have changed twice now, and each time this test failed for a reason that
	// had nothing to do with what it is checking.
	m.cursor = m.rowIndex(focusContainer)
	if got := m.selectedApp(); got != -1 {
		t.Errorf("a container row must not select an app, got %d", got)
	}
	if c := m.focusedContainer(); c == nil || c.name != "blog-web-1" {
		t.Errorf("focusedContainer did not find the container: %+v", c)
	}
	// An app row is not a container.
	m.cursor = m.rowIndex(focusApp)
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
	m := openAddForm(testModel())
	// In the footer, with the list still behind it.
	if m.prompt == nil || m.prompt.kind != promptForm {
		t.Fatalf("the add row did not open the form, got %v", m.prompt)
	}
	if m.scr != screenIndex {
		t.Errorf("the form should not take over the screen, got %v", m.scr)
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
	if m.prompt == nil {
		t.Error("form should stay open when a field is invalid")
	}
	if !strings.Contains(m.form.problem, "tag") {
		t.Errorf("expected a complaint about the tag, got %q", m.form.problem)
	}
}

func TestTheAddFormKeepsTheListInView(t *testing.T) {
	// The whole reason it moved into the footer: the apps already on the box
	// stay on screen while you type the name of a new one.
	m := testModel()
	m.width, m.height = 90, 26
	m = openAddForm(m)
	m.reflow()

	v := stripANSI(m.View())
	for _, want := range []string{"blog", "shop", "Add an app", "app name", "config image"} {
		if !strings.Contains(v, want) {
			t.Errorf("%q should be on screen with the form open:\n%s", want, v)
		}
	}
	if n := len(strings.Split(v, "\n")); n != m.height {
		t.Errorf("the form made the page %d lines, want %d", n, m.height)
	}
	// esc puts the keys back without leaving the list.
	back := send(m, "esc")
	if back.prompt != nil || back.scr != screenIndex {
		t.Error("esc should close the form and leave you on the list")
	}
}

func TestAddFormRejectsABadAppName(t *testing.T) {
	m := openAddForm(testModel())
	for _, r := range "bad name" {
		m = send(m, string(r))
	}
	m = send(m, "tab")
	for _, r := range "ghcr.io/you/x-config" {
		m = send(m, string(r))
	}
	m = send(m, "enter", "enter")
	if m.prompt == nil || m.form.problem == "" {
		t.Error("a space in the app name should be rejected")
	}
}

func TestRemoveRequiresTypingTheAppName(t *testing.T) {
	m := send(testModel(), "x")
	if m.prompt == nil {
		t.Fatal("'x' did not ask anything")
	}
	if m.scr != screenIndex {
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
	// One key answers it, and the operation takes the footer the question was
	// asked in rather than a screen of its own.
	next := send(m, "y")
	if !next.running() {
		t.Error("y should answer a plain confirmation and start the work")
	}
	if next.scr != screenIndex {
		t.Errorf("rotating should not leave the list, got %v", next.scr)
	}
}

func TestAnOperationRunsInTheFooter(t *testing.T) {
	// Every operation used to blank the page, stream a few hundred lines of apk
	// and docker output, and finish on a page of results. The output was never
	// the point -- it was there because the operation had taken the screen and
	// something had to fill it.
	m := testModel()
	m.width, m.height = 90, 24
	m.cursor = rowOf(m, focusApp)
	m = send(m, "r", "y")

	if !m.running() || m.scr != screenIndex {
		t.Fatalf("rotating should run in the footer over the list, got %v", m.scr)
	}
	v := stripANSI(m.View())
	if !strings.Contains(v, "Rotating the deploy key for blog") {
		t.Error("the footer should say what it is doing, as a statement")
	}
	// The list it was started from is still there, and still the whole page.
	if !strings.Contains(v, "shop") {
		t.Error("the list should stay visible while the work runs")
	}
	if n := len(strings.Split(v, "\n")); n != m.height {
		t.Errorf("the page is %d lines, want %d", n, m.height)
	}
	// Keys do nothing until it comes back -- there is nothing to press.
	for _, k := range []string{"enter", "x", "up", "esc"} {
		if next := send(m, k); !next.running() {
			t.Errorf("%q should do nothing mid-operation", k)
		}
	}

	// Something to hand over stays in the footer until it is dismissed.
	next, _ := m.Update(runDoneMsg{result: &addResult{
		app: "blog", keyPath: "/k", knownHosts: "h k b", onClipboard: -1}})
	after := next.(model)
	if after.prompt == nil || after.prompt.kind != promptResult {
		t.Fatal("a result should stay in the footer")
	}
	if !strings.Contains(stripANSI(after.View()), "KOMIZO_DEPLOY_KEY") {
		t.Error("the values are the whole reason this screen existed")
	}
	if done := send(after, "enter"); done.prompt != nil {
		t.Error("enter should dismiss the result")
	}
}

func TestAnythingThatChangesTheBoxReReadsIt(t *testing.T) {
	// The poll is every five seconds; a change you just made should be on
	// screen before that. Every path that touches the server ends in a read --
	// including the ones that failed, because a command that reports failure is
	// exactly when the rows are least trustworthy: a `compose up` can start two
	// of three services and fail on the third.
	m := testModel()
	m.busy = map[string]bool{"app:blog": true}

	for name, msg := range map[string]tea.Msg{
		"start or stop":      opDoneMsg{key: "app:blog"},
		"a failed start":     opDoneMsg{key: "app:blog", err: fmt.Errorf("no such service")},
		"an operation":       runDoneMsg{},
		"a failed operation": runDoneMsg{err: fmt.Errorf("exit status 1")},
		"one with a result":  runDoneMsg{result: &addResult{app: "blog", keyPath: "/k"}},
	} {
		next, cmd := m.Update(msg)
		if cmd == nil {
			t.Errorf("%s: should have re-read the box", name)
		}
		if !next.(model).fetching {
			t.Errorf("%s: the read should be recorded as in flight", name)
		}
	}
}

func TestAFailedOperationKeepsItsOutput(t *testing.T) {
	// The stream is collected and never shown -- but "exit status 1" on its own
	// diagnoses nothing, so the last lines come back when something fails.
	m := testModel()
	m.width, m.height = 90, 24
	m.cursor = rowOf(m, focusApp)
	m = send(m, "r", "y")
	m.run.lines = []string{"+ doas rotate-blog", "doas: authentication failed", "Killed"}

	next, _ := m.Update(runDoneMsg{err: fmt.Errorf("ssh: exit status 1")})
	v := stripANSI(next.(model).View())
	for _, want := range []string{"failed", "exit status 1", "authentication failed", "Killed"} {
		if !strings.Contains(v, want) {
			t.Errorf("a failure should show %q:\n%s", want, v)
		}
	}
}

func TestEscLeavesEveryScreen(t *testing.T) {
	for _, open := range []string{"x", "r", "c"} {
		m := send(testModel(), open, "esc")
		if m.scr != screenIndex || m.prompt != nil {
			t.Errorf("esc from %q did not close the question, got %v", open, m.scr)
		}
	}
	// Including the form, which is a question like the others now.
	if m := send(openAddForm(testModel()), "esc"); m.prompt != nil {
		t.Error("esc should close the add form")
	}
}

func TestTheDeployKeyIsNeverWrittenDown(t *testing.T) {
	// The point of generating it in memory: nothing about the interface path
	// takes a filename, so there is nowhere for it to be written even by
	// accident. The result carries the key itself, and copying reads that.
	r := &addResult{app: "blog", key: "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n",
		knownHosts: "box ssh-ed25519 AAAA", onClipboard: -1}
	if r.keyPath != "" {
		t.Error("the interface never asks for a copy on disk")
	}

	// A config-image change must not issue a new one: it is a setting change,
	// and a repo whose deploy key silently changed underneath it fails on its
	// next push for a reason nobody would connect to what they just did.
	plan := addPlan{tgt: target{host: "box"}, app: "blog", user: "komizo-blog",
		config: "ghcr.io/you/blog-config", keepKey: true}
	if !plan.keepKey {
		t.Error("a config change should keep the key already on the server")
	}

	// And every generated key is genuinely new.
	a, err := newKeypair(keyComment("komizo-blog", "box"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newKeypair(keyComment("komizo-blog", "box"))
	if a.private == b.private || a.public == b.public {
		t.Error("two rotations should produce two keys")
	}
}

func TestResultShowsBothValuesToPaste(t *testing.T) {
	r := addResult{
		app:        "blog",
		key:        "-----BEGIN OPENSSH PRIVATE KEY-----\nxxxx\n",
		knownHosts: "box ssh-ed25519 AAAA",
	}
	v := r.view()
	for _, want := range []string{"KOMIZO_DEPLOY_KEY", "KOMIZO_KNOWN_HOSTS", "press c to copy", "app: blog"} {
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
		"route\tblog\tblog.example.com\tblog-web\t8080",
		"app\tworker\tcd-worker\t/srv/worker\tnone\t0\tghcr.io/you/worker-config\t",
		"proxy\trunning\tedge\tcaddy:2\tUp 3 hours\t2026-07-27T09:00:00Z\t0001-01-01T00:00:00Z\t0",
		"net\tedge\tbridge\t172.18.0.0/16",
		"netmember\tkomizo-proxy\tkomizo-proxy",
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
	_, _, proxy, _, _ := parseInventory("app\tblog\tcd-blog\t/srv/blog\ta1b2\t2\tghcr.io/you/blog-config\t\t")
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
	// No heading over them any more -- the facts are the point, not the label.
	v := netModel().View()
	for _, want := range []string{
		"box.example.com", // which box, in the header
		"alpine",          // os
		"komizo server",   // the version the box was set up with
		"edge", "bridge",  // network, on the proxy row
	} {
		if !strings.Contains(v, want) {
			t.Errorf("the list is missing %q", want)
		}
	}
	// No docker row: its version was a fact nobody acted on.
	if strings.Contains(v, "Docker version") {
		t.Errorf("the docker row should be gone:\n%s", v)
	}
}

func TestAStoppedProxyIsCalledOutWithoutNavigating(t *testing.T) {
	m := netModel()
	m.proxy = proxyRow{installed: true, state: "stopped", network: "edge",
		image: "caddy:2", status: "Exited (0) 5 minutes ago"}
	// The word "stopped" is gone -- the red dot is the whole signal now.
	if g, _ := m.proxyLine(); g != dot("err") {
		t.Error("a stopped proxy should show the red dot")
	}
	// What it means for the apps is the red dot on every one of them, plus the
	// proxy's own red dot -- there is no summary block any more.
	m.cursor = rowOf(m, focusProxy)
	if got := m.keyLabel("s"); got != "start" {
		t.Errorf("s on a stopped proxy should offer to start, got %q", got)
	}

	m.proxy = proxyRow{}
	v := m.View()
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
	if m.scr != screenSetup {
		t.Fatalf("a bare server should open the init screen, got %v", m.scr)
	}
	// The state of the box, a line about what it is for, and the question.
	// What gets installed is in docs/server.md; this screen used to list it
	// piece by piece, which is implementation detail for someone who has not
	// decided to use the tool yet.
	// The tagline by reference, not by a word out of it: this assertion has
	// outlived one rewording already, and a literal here fails on the next one
	// without anything actually being wrong.
	v := strings.ToLower(m.View())
	for _, want := range []string{"not set up yet", strings.ToLower(tagline), "start", "cancel"} {
		if !strings.Contains(v, want) {
			t.Errorf("setup screen is missing %q", want)
		}
	}
	if strings.Contains(v, "the network apps share") {
		t.Error("the setup screen should not list what each piece is")
	}
}

func TestReadyServerGoesStraightToTheList(t *testing.T) {
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40
	next, _ := m.Update(appsMsg{srv: serverRow{state: "ready"}})
	if next.(model).scr != screenIndex {
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
	if m.logs != "" || m.scroll != 0 {
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
	if back := send(m, "esc"); back.scr != screenIndex {
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
	if m.scroll != 0 {
		t.Errorf("scrolled above the first line: %d", m.scroll)
	}
	for i := 0; i < 200; i++ {
		m = send(m, "down")
	}
	if want := m.maxScroll(); m.scroll != want {
		t.Errorf("scrolled past the end: %d, want %d", m.scroll, want)
	}
	// Shift with the arrow you are already using goes to the ends. It replaced
	// g/G, home/end, pgup/pgdn, space, f and b -- six pairs of undocumented
	// keys for a window that shows one screenful of text.
	if got := send(m, "shift+up").scroll; got != 0 {
		t.Errorf("shift+up should go to the top, got %d", got)
	}
	if got := send(m, "shift+down").scroll; got != m.maxScroll() {
		t.Errorf("shift+down should go to the bottom, got %d", got)
	}
	// A log that fits needs no scrolling at all.
	m.logs = "one\ntwo"
	if m.maxScroll() != 0 {
		t.Error("a log that fits should not scroll")
	}
}

func TestStoppedProxyIsShouted(t *testing.T) {
	m := netModel()
	m.proxy = proxyRow{installed: true, state: "stopped", network: "edge", status: "Exited (0) 5 minutes ago"}
	// No word "stopped" any more: the red dot is what calls it out, and every row
	// on the page says its state in that one column of colour rather than in prose.
	if g, _ := m.proxyLine(); g != dot("err") {
		t.Error("a stopped proxy should show the red dot")
	}
	// With the proxy selected, s offers to start it rather than stop it.
	m.cursor = rowOf(m, focusProxy)
	if got := m.keyLabel("s"); got != "start" {
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
	if !strings.Contains(v, "proxy / logs") {
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
			{container: "komizo-proxy", aliases: []string{"komizo-proxy"}},
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
	if !strings.Contains(v, "no shared network") {
		t.Error("a box with no network should say so")
	}
	// The fix is re-running setup, which lives on the komizo server row.
	if !strings.Contains(stripANSI(v), "komizo server row") {
		t.Error("it should point at where the fix lives")
	}
}

// The os row is read off the box -- PRETTY_NAME out of /etc/os-release --
// rather than assumed. komizo installs Alpine, but it is pointed at existing
// servers too, and "alpine" about a Debian box is wrong in the row whose whole
// job is stating facts.
func TestTheOSIsReadOffTheBox(t *testing.T) {
	_, srv, _, _, _ := parseInventory("server\tready\tDocker version 26\nos\tAlpine Linux v3.20\n")
	if srv.osName() != "Alpine Linux v3.20" {
		t.Errorf("os = %q, want what the box reported", srv.osName())
	}
	// A box that reported nothing still names what komizo installs, rather
	// than an empty row.
	if got := (serverRow{}).osName(); got != "alpine" {
		t.Errorf("fallback os = %q, want alpine", got)
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

func TestUpdatingKomizoDoesNotReopenTheSetupForm(t *testing.T) {
	// Update is a prompt, not the first-run form. Reopening the form would put
	// the proxy question back in front of someone who only meant to update, and a
	// box that deliberately has no proxy stays that way -- the update's proxy step
	// runs only where one already exists.
	m := testModel()
	m.proxy = proxyRow{} // no proxy on this box, by choice
	m.cursor = rowOf(m, focusKomizo)
	m = send(m, "u")
	if m.scr == screenSetup {
		t.Fatal("update must not reopen the first-run form")
	}
	if m.prompt == nil {
		t.Fatal("update should ask first")
	}
	// Asserted on the text rather than the render: the footer wraps to the
	// terminal, so a phrase can straddle two lines and still be shown.
	d := m.prompt.question + " " + m.prompt.detail
	if !strings.Contains(d, "Docker") {
		t.Error("the update re-runs the whole setup, so it should say Docker")
	}
	if !strings.Contains(d, "apps keep running") {
		t.Error("it should say apps are unaffected")
	}
}

// The proxy used to be a question of its own on this screen, and the test that
// lived here checked it was still asked about on a bare box. It is not asked
// about at all any more -- every box gets one, since an app nobody can reach is
// not a deployment -- and TestInitAlwaysInstallsTheProxy covers that the
// defaults still carry it.

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
	if m.scr != screenSetup {
		t.Fatalf("a bare server should open the init screen, got %v", m.scr)
	}
	v := m.View()
	// One decision, and it is on the page rather than in the footer: two
	// buttons, yes selected.
	for _, want := range []string{"start", "cancel", "enter", "select"} {
		if !strings.Contains(v, want) {
			t.Errorf("the setup screen should show %q:\n%s", want, v)
		}
	}
	// No question about the proxy survives anywhere on it.
	for _, gone := range []string{"reverse proxy?", "tab next"} {
		if strings.Contains(v, gone) {
			t.Errorf("setup screen still contains %q -- it should ask one thing", gone)
		}
	}
	// And enter hands the page over to the loader. What is about to be
	// installed was worth reading while it was a decision; once it is running,
	// leaving the description up behind a spinner reads as though it is still
	// asking.
	m = send(m, "enter")
	if !m.running() {
		t.Error("enter should start the setup")
	}
	if m.scr != screenLoading {
		t.Errorf("setting up should hand over to the loader, got %v", m.scr)
	}
	v = stripANSI(m.View())
	if !strings.Contains(v, "Setting up") {
		t.Error("the loader should say what it is doing")
	}
	if strings.Contains(v, "installs") {
		t.Error("the description should be gone once it is running")
	}
}

func TestSetupHasTwoButtons(t *testing.T) {
	m := testModel()
	m.width, m.height = 76, 20
	m.scr = screenSetup

	// Start to start with: someone who reached this screen connected to a
	// server on purpose, and defaulting to cancel makes the common case the
	// extra press.
	if m.setupCancel {
		t.Error("start should be selected first")
	}
	// Either arrow moves between them, and the pair keeps its width so the
	// line does not slide sideways under the key that moved it.
	wide := lipglossWidth(m.setupButtons())
	for _, k := range []string{"right", "left", "tab"} {
		next := send(m, k)
		if next.setupCancel == m.setupCancel {
			t.Errorf("%q should move between the buttons", k)
		}
		if got := lipglossWidth(next.setupButtons()); got != wide {
			t.Errorf("%q changed the width of the pair: %d -> %d", k, wide, got)
		}
	}

	// Enter on start does the work; enter on cancel leaves, because setting the
	// server up is the only thing this screen does.
	if go_ := send(m, "enter"); !go_.running() || go_.scr != screenLoading {
		t.Error("enter on start should begin the setup")
	}
	cancel := send(m, "right")
	next, cmd := cancel.Update(key("enter"))
	if next.(model).running() {
		t.Error("enter on cancel should not start anything")
	}
	if cmd == nil {
		t.Error("cancel should quit rather than leave you on a page with no next step")
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
	// This screen ends up in screenshots and scrollback. The key is in the
	// process and on the clipboard once you press c; it is never on the page,
	// on any code path -- and there is no longer a file to name instead.
	base := addResult{app: "ormos",
		key:        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n",
		knownHosts: "1.2.3.4 ssh-ed25519 AAAAC3Nza"}
	for _, r := range []addResult{
		base,
		{app: base.app, key: base.key, knownHosts: base.knownHosts, onClipboard: resultKey},
		{app: base.app, key: base.key, knownHosts: base.knownHosts, copyErr: "no clipboard tool found"},
		{app: base.app, key: base.key, knownHosts: base.knownHosts, rotated: true},
	} {
		v := r.view()
		for _, forbidden := range []string{"PRIVATE KEY", "BEGIN OPENSSH", "b3BlbnNzaC1rZXktdjEA"} {
			if strings.Contains(v, forbidden) {
				t.Errorf("the result screen must never render key material (%q)", forbidden)
			}
		}
	}
}

func TestResultDoesNotLookLikeTheValueIsACatCommand(t *testing.T) {
	// "cat /home/..." sat alone under KOMIZO_DEPLOY_KEY, which reads like a value
	// and invited pasting that literal string into the secret. There is no file
	// any more, so what has to be clear is that the value is on the clipboard.
	v := addResult{app: "ormos", key: "k", knownHosts: "h k b"}.view()
	if !strings.Contains(v, "not shown") {
		t.Error("the screen must say why there is no value printed under the name")
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
	m = showResult(m, r)

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
			if strings.Contains(ln, "clipboard") && strings.Contains(ln, "KOMIZO_DEPLOY_KEY") {
				onKey = true
			}
			if strings.Contains(ln, "clipboard") && strings.Contains(ln, "KOMIZO_KNOWN_HOSTS") {
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
	// Both values are copied the same way now -- out of memory -- so this
	// drives the mark rather than a failure: copying one must not leave the
	// other still claiming to be on the clipboard.
	//
	// The clipboard itself is stubbed. A headless machine has no clipboard
	// tool, so the real one fails and every mark lands on -1 -- which passed
	// locally, failed on the first CI run, and would have gone on passing on
	// the machine where nobody needed it to.
	stubClipboard(t)
	m := showResult(testModel(), &addResult{app: "a",
		key: "-----BEGIN OPENSSH PRIVATE KEY-----\n", knownHosts: "h k b", onClipboard: -1})

	m = send(m, "down", "c")
	if m.run.result.onClipboard != resultHosts {
		t.Fatalf("host keys should be on the clipboard, got %d", m.run.result.onClipboard)
	}
	m = send(m, "up", "c")
	if m.run.result.onClipboard != resultKey {
		t.Error("the mark should move to the value just copied")
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
	// All of them ask in the footer now, adding included.
	if next := openAddForm(m); next.prompt == nil {
		t.Error("the add row is advertised on the list but does nothing")
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
	if m.scr != screenIndex {
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
	if m.scr != screenIndex {
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
		"app\tblog\tkomizo-blog\t/srv/blog\ta1b2c3d\t2\tghcr.io/you/blog-config\t",
		"container\tblog\tweb\tblog-web-1\trunning\tUp 3 hours\t2026-07-27T09:00:00.123456789Z\t0001-01-01T00:00:00Z\t0\tghcr.io/you/blog-web:a1b2c3d\t8080",
		"container\tblog\tdb\tblog-db-1\texited\tExited (1) 2 minutes ago\t2026-07-27T08:00:00Z\t2026-07-27T09:30:00Z\t1\tghcr.io/you/blog-db:a1b2c3d\t",
		"route\tblog\tblog.example.com,www.blog.example.com\tblog-web\t8080",
		"app\tshop\tkomizo-shop\t/srv/shop\tnone\t0\tghcr.io/you/shop-config\t",
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
	got := stripANSI(viewIndex(m))

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
	// add meant the screen meant to be the durable home for KOMIZO_KNOWN_HOSTS
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
	// move, so presenting KOMIZO_KNOWN_HOSTS as something to copy would say
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
	if !strings.Contains(fresh.view(), "KOMIZO_KNOWN_HOSTS") {
		t.Error("a fresh setup should still show the host keys")
	}
}

func TestRotationCopiesItselfAndComesBack(t *testing.T) {
	// A rotation produces one value: the host keys did not move, so the deploy
	// key is the only thing to choose between, and a screen offering one choice
	// asks you to press a key it already knows the answer to. It goes to the
	// clipboard and the index comes back with a line saying so.
	if !clipboardAvailable() {
		t.Skip("no clipboard tool")
	}
	m := testModel()
	m.width, m.height = 90, 24
	m.cursor = rowOf(m, focusApp)
	m = send(m, "r", "y")
	if !m.running() {
		t.Fatal("y should start the rotation")
	}

	rotated := &addResult{app: "blog", rotated: true, onClipboard: -1,
		key: "-----BEGIN OPENSSH PRIVATE KEY-----\nrotated\n-----END OPENSSH PRIVATE KEY-----\n"}
	next, cmd := m.Update(runDoneMsg{result: rotated})
	after := next.(model)

	if after.prompt != nil {
		t.Error("a rotation should not leave a screen to dismiss")
	}
	if after.scr != screenIndex {
		t.Errorf("it should come back to the index, got %v", after.scr)
	}
	if !strings.Contains(after.status, "copied") || after.statusErr {
		t.Errorf("it should say the key was copied, got %q", after.status)
	}
	if !strings.Contains(after.status, "KOMIZO_DEPLOY_KEY") {
		t.Errorf("it should say where the key goes, got %q", after.status)
	}
	if cmd == nil {
		t.Error("the box should be re-read after a rotation")
	}

	// Adding keeps the screen: there are two values, and which one you want is
	// a choice only the person pasting them can make.
	fresh := &addResult{app: "blog", onClipboard: -1, key: "k", knownHosts: "box ssh-ed25519 AAAA"}
	next, _ = m.Update(runDoneMsg{result: fresh})
	if p := next.(model).prompt; p == nil || p.kind != promptResult {
		t.Error("adding an app should still show both values")
	}
}

func TestAppsAreGrouped(t *testing.T) {
	// Each app and its containers read as a block. Without the gap the whole
	// section was one column and the eye had to find the app rows by their
	// indentation; without dropping the one under the heading, the first block
	// sat lower than the rest and read as though something were missing.
	m := testModel()
	m.width, m.height = 90, 30
	m.apps = []appRow{
		{name: "blog", running: "1", containers: []containerRow{
			{app: "blog", service: "web", name: "blog-web-1", state: "running"}}},
		{name: "shop", running: "1", containers: []containerRow{
			{app: "shop", service: "web", name: "shop-web-1", state: "running"}}},
	}
	m.reflow()
	lines := strings.Split(stripANSI(m.View()), "\n")

	at := func(want string) int {
		for i, ln := range lines {
			if strings.Contains(ln, want) {
				return i
			}
		}
		t.Fatalf("%q is not on the page:\n%s", want, strings.Join(lines, "\n"))
		return -1
	}
	// The apps have no heading. They are still set off from the box's own rows
	// by one blank line -- the separation the heading used to carry, which the
	// tree needs and the label did not.
	first := at("blog")
	if strings.TrimSpace(lines[first-1]) != "" {
		t.Errorf("the app list should be preceded by a blank line, got %q", lines[first-1])
	}
	if strings.TrimSpace(lines[first-2]) == "" {
		t.Errorf("one blank line, not two:\n%s", strings.Join(lines, "\n"))
	}
	// The next app is separated from the one above by a blank line.
	if blank := at("shop") - 1; strings.TrimSpace(lines[blank]) != "" {
		t.Errorf("apps should be separated by a blank line, got %q", lines[blank])
	}
	// And the blank rows are not somewhere the cursor can land: every position
	// still marks exactly one row, which the next test covers across shapes.
	for cursor := range m.focusItems() {
		m.cursor = cursor
		m.reflow()
		if n := strings.Count(m.View(), cursorBar); n != 1 {
			t.Errorf("cursor %d marks %d rows, want 1", cursor, n)
		}
	}
}

func TestExactlyOneRowIsEverMarked(t *testing.T) {
	// The cursor is one row. Two places used to work out where the app rows
	// start by recounting the rows above them, and a recount is a second
	// definition of the same thing -- when the known_hosts row left the focus
	// list, both kept counting it. Every row below was then numbered one too
	// high: the cursor highlighted one row while the keys acted on another,
	// and on a box with one app and no containers the app row and "+ add an
	// app" lit up together, the app having been handed the add row's index.
	//
	// Walked over the shapes that move the numbering: whether the server's
	// keys have been read, whether a proxy is installed, whether an app has
	// containers of its own.
	for name, m := range map[string]model{
		"a bare app": {
			srv:   serverRow{state: "ready", docker: "26.1.3", hostKeys: [][2]string{{"ssh-ed25519", "AAAA"}}},
			proxy: proxyRow{installed: true, state: "running"},
			apps:  []appRow{{name: "blog"}},
		},
		"no host keys yet": {
			srv:   serverRow{state: "ready", docker: "26.1.3"},
			proxy: proxyRow{installed: true, state: "running"},
			apps:  []appRow{{name: "blog"}},
		},
		"no proxy": {
			srv:  serverRow{state: "ready", docker: "26.1.3", hostKeys: [][2]string{{"ssh-ed25519", "AAAA"}}},
			apps: []appRow{{name: "blog"}},
		},
		"apps with containers": {
			srv:   serverRow{state: "ready", docker: "26.1.3", hostKeys: [][2]string{{"ssh-ed25519", "AAAA"}}},
			proxy: proxyRow{installed: true, state: "running"},
			apps: []appRow{
				{name: "blog", running: "1", containers: []containerRow{
					{app: "blog", service: "web", name: "blog-web-1", state: "running"}}},
				{name: "shop"},
			},
		},
	} {
		m.scr = screenIndex
		m.tgt = target{user: "root", host: "box.example.com", port: 22}
		m.width, m.height = 100, 40
		for cursor := range m.focusItems() {
			m.cursor = cursor
			m.reflow()
			marked := 0
			for _, ln := range strings.Split(m.View(), "\n") {
				if strings.Contains(ln, cursorBar) {
					marked++
				}
			}
			if marked != 1 {
				t.Errorf("%s: cursor %d marks %d rows, want 1:\n%s",
					name, cursor, marked, stripANSI(m.View()))
			}
		}
	}
}

func TestNothingIsCopiedWithATrailingNewline(t *testing.T) {
	// Everything this copies is pasted into a text field in a browser, where a
	// trailing newline is a blank last line that gets saved as part of the
	// value. Trimmed at the clipboard rather than at each call site, so no
	// future copy path can put one back.
	//
	// The private key included. The newline after the PEM terminator is what a
	// FILE wants, and the deploy action writes the secret out with
	// printf '%s\n', which supplies exactly one on the way back.
	kp, err := newKeypair(keyComment("komizo-blog", "box"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(kp.private, "-----\n") {
		t.Error("the generated key should end with the PEM terminator and its newline")
	}
	for name, s := range map[string]string{
		"a private key":  kp.private,
		"host keys":      "box ssh-ed25519 AAAA\nbox ssh-rsa BBBB\n",
		"several blanks": "value\n\n\n",
		"a log":          "line one\nline two\n",
	} {
		if got := clipboardText(s); strings.HasSuffix(got, "\n") {
			t.Errorf("%s: copied with a trailing newline: %q", name, got[len(got)-20:])
		}
	}
	// Only at the end: the newlines that separate lines are the value.
	if got := clipboardText("a\nb\n"); got != "a\nb" {
		t.Errorf("interior newlines must survive, got %q", got)
	}

	hosts := formatKnownHosts(target{host: "box", port: 22}, [][2]string{
		{"ssh-ed25519", "AAAA"}, {"ssh-rsa", "BBBB"},
	})
	if lines := strings.Split(hosts, "\n"); len(lines) != 2 {
		t.Errorf("expected one line per key, got %d: %q", len(lines), hosts)
	}
}

func TestKnownHostsIsCopiedPerApp(t *testing.T) {
	// The KEYS belong to the box and every app pins the same ones; the NAMES
	// belong to the repo, because known_hosts is matched on the exact string
	// the client dialled and each repo dials one name. So the value is built
	// per app, from that app's recorded names.
	//
	// It used to be one server-wide row built from every name every app had
	// mentioned in the session, which put one app's hostnames in another app's
	// repository -- and lost them entirely on the next run, since nothing wrote
	// them down.
	m := netModel()
	m.srv.hostKeys = [][2]string{
		{"ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAI"},
		{"ssh-rsa", "AAAAB3NzaC1yc2EAAAADAQABA"},
	}
	m.apps = []appRow{
		{name: "blog", knownAs: []string{"blog.example.com"}},
		{name: "shop", knownAs: []string{"shop.example.com"}},
	}

	blog := formatKnownHosts(m.tgt.namedFor(m.apps[0].knownAs), m.srv.hostKeys)
	if !strings.Contains(blog, "blog.example.com ssh-ed25519") {
		t.Errorf("blog's value should name blog: %q", blog)
	}
	if strings.Contains(blog, "shop.example.com") {
		t.Error("blog's value must not carry another app's hostnames")
	}
	// The name this session connected by is in it too: that is what CI dials
	// when a repo was set up without extra names.
	if !strings.Contains(blog, m.tgt.host) {
		t.Errorf("the connected name should be covered: %q", blog)
	}

	// Offered on the app's own row, beside the other things that act on it.
	m.cursor = rowOf(m, focusApp)
	if !strings.Contains(stripANSI(m.pageFooter()), "hosts") {
		t.Error("the app row should offer its known_hosts")
	}
	// And nowhere else: the komizo server row has no known_hosts of its own.
	m.cursor = rowOf(m, focusKomizo)
	if strings.Contains(stripANSI(m.pageFooter()), "hosts") {
		t.Error("known_hosts is not a server-level value")
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
	// The keys do the obvious thing to whatever is selected, which is only not
	// a guessing game if the hint changes with it.
	m := testModel()
	m.srv.hostKeys = [][2]string{{"ssh-ed25519", "AAAA"}}
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 3 hours"},
	}

	// By kind, not by index: the gate row now sits between the proxy and the
	// apps, and a hardcoded index moves every time a row is added.
	for _, c := range []struct {
		kind focusKind
		key  string
		want string
	}{
		{focusKomizo, "u", "update"},  // the komizo the box was set up with
		{focusProxy, "s", "stop"},     // proxy, at the head of the live block
		{focusApp, "s", "stop"},       // app, running
		{focusContainer, "s", "stop"}, // container, running
	} {
		m.cursor = rowOf(m, c.kind)
		if got := m.keyLabel(c.key); got != c.want {
			t.Errorf("%v: %s is labelled %q, want %q", c.kind, c.key, got, c.want)
		}
		// And enter is the monitor on every one of them (the gate row is the one
		// exception, checked below).
		if got := m.keyLabel("enter"); got != "monitor" {
			t.Errorf("%v: enter is labelled %q, want \"monitor\"", c.kind, got)
		}
	}

	// The gate row has no monitor: enter edits it.
	m.cursor = rowOf(m, focusGate)
	if got := m.keyLabel("enter"); got != "set gate" && got != "change gate" {
		t.Errorf("gate row: enter is labelled %q, want \"set gate\"/\"change gate\"", got)
	}

	// The log key is offered on both, labelled the same. It used to name the
	// row -- "l web log", "l blog log" -- which repeated the cursor back at you
	// and made the footer's width depend on how long an app was called. Which
	// log it opens is still the selected row's, and the window it opens says so
	// in its title.
	for _, k := range []focusKind{focusContainer, focusApp} {
		m.cursor = rowOf(m, k)
		if !strings.Contains(stripANSI(m.pageFooter()), "l logs") {
			t.Errorf("%v: l should be offered", k)
		}
	}
}

func TestUOnTheKomizoRowUpdatesTheServer(t *testing.T) {
	// The action sits on the row showing the thing it changes: re-running setup
	// is what moves that version, so the version is where you press it. There
	// is no second way to reach it -- a global key as well would be two routes
	// to one action, and one of them undiscoverable from the row it affects.
	m := netModel()
	m.cursor = rowOf(m, focusKomizo)
	m = send(m, "u")
	if m.prompt == nil {
		t.Fatal("u on the komizo row should ask about an update")
	}
	// It re-runs the whole setup, and must be clear the apps are not touched,
	// since that is the fear.
	if !strings.Contains(m.prompt.detail, "Docker") {
		t.Errorf("the question should say it re-runs the setup: %q", m.prompt.detail)
	}
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
	m = send(m, "s") // asks first
	if m.prompt == nil {
		t.Fatal("start/stop should ask before acting")
	}
	m, cmd := sendCmd(m, "y")
	if m.scr != screenIndex {
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
	// "u" only does something on the komizo server row; there is no global key.
	m := testModel()
	m.cursor = rowOf(m, focusApp) // deliberately NOT the komizo server row
	if next := send(m, "u"); next.scr != screenIndex {
		t.Errorf("'u' should no longer do anything, got %v", next.scr)
	}
	if strings.Contains(m.View(), "update server") {
		t.Error("the help should not advertise a key that does nothing")
	}
}

func TestAppKeysOnlyOfferedWithAnAppSelected(t *testing.T) {
	// Offering "rotate key" with the cursor on the komizo server row offers it for
	// nothing: there is no app for it to apply to, so the hint is a small lie.
	m := testModel()

	m.cursor = rowOf(m, focusKomizo)
	v := stripANSI(m.pageFooter())
	for _, k := range []string{"rotate", "remove", "config"} {
		if strings.Contains(v, k) {
			t.Errorf("%q should not be offered with no app selected:\n%s", k, v)
		}
	}
	// And pressing them does nothing rather than acting on some other app.
	for _, k := range []string{"c", "r", "x"} {
		if next := send(m, k); next.scr != screenIndex {
			t.Errorf("%q with no app selected should do nothing, got %v", k, next.scr)
		}
	}
	// Adding is not among them at all now: it is its own row under the list,
	// so it needs no key and cannot be pressed by accident from an app.
	if next := send(m, "a"); next.scr != screenIndex {
		t.Errorf("'a' should no longer do anything, got %v", next.scr)
	}

	m.cursor = rowOf(m, focusApp)
	f := stripANSI(m.pageFooter())
	for _, k := range []string{"rotate", "remove", "config"} {
		if !strings.Contains(f, k) {
			t.Errorf("%q should be offered with an app selected:\n%s", k, f)
		}
	}

	// A container row does NOT count. The keys are app-wide, so offering them
	// next to one container's name would say something untrue.
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running"},
	}
	m.cursor = rowOf(m, focusContainer)
	cf := stripANSI(m.pageFooter())
	for _, gone := range []string{"rotate", "remove", "config"} {
		if strings.Contains(cf, gone) {
			t.Errorf("%q must not be offered on a container row:\n%s", gone, cf)
		}
	}
	for _, k := range []string{"c", "r", "x"} {
		if next := send(m, k); next.scr != screenIndex {
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
	if next := openAddForm(m); next.prompt == nil {
		t.Error("the add row should open the form on an empty box")
	}
}

func TestHelpIsOneLineInAFixedOrder(t *testing.T) {
	// One line: move, act, the row's own keys, leave. The order is what the
	// second line used to do -- "select" and "quit" are in the same place on
	// every screen, and what changes as the cursor moves is the middle.
	m := testModel()
	m.srv.hostKeys = [][2]string{{"ssh-ed25519", "AAAA"}}

	for _, k := range []focusKind{focusKomizo, focusProxy, focusApp} {
		m.cursor = rowOf(m, k)
		v := stripANSI(m.View())
		for _, always := range []string{"quit", "select"} {
			if !strings.Contains(v, always) {
				t.Errorf("%v: %q must be offered from every row", k, always)
			}
		}
	}

	// The app keys are absent from rows they cannot act on.
	m.cursor = rowOf(m, focusKomizo)
	for _, gone := range []string{"rotate", "remove", "config", "reinstall"} {
		if strings.Contains(stripANSI(m.pageFooter()), gone) {
			t.Errorf("%q should not be offered on the komizo server row", gone)
		}
	}
	// And present on one they can.
	m.cursor = rowOf(m, focusApp)
	if !strings.Contains(stripANSI(m.pageFooter()), "rotate") {
		t.Error("the app row should offer the app keys")
	}
}

func TestTheFooterIsOneLineAtAnyWidth(t *testing.T) {
	m := testModel()
	m.cursor = rowOf(m, focusApp)

	// Move first, enter next, the row's own keys after it, leave last.
	for _, w := range []int{200, 100, 80} {
		m.width = w
		line := strings.TrimSpace(stripANSI(m.helpLines()))
		if n := strings.Count(strings.TrimSpace(stripANSI(m.pageFooter())), "\n"); n > 2 {
			t.Errorf("width %d: the footer is more than one line of keys", w)
		}
		if !strings.HasPrefix(line, "↑↓ select") {
			t.Errorf("width %d: %q should start with select", w, line)
		}
		if !strings.HasSuffix(line, "q quit") {
			t.Errorf("width %d: %q should end with quit", w, line)
		}
		if i, j := strings.Index(line, "enter"), strings.Index(line, "· c "); i < 0 || (j > 0 && i > j) {
			t.Errorf("width %d: enter should lead the row's own keys: %q", w, line)
		}
	}

	// Narrow enough that not everything fits. The two that work on every screen
	// survive, the row's own keys go, and an ellipsis says they went -- rather
	// than the line being clipped, which would take "q quit" off the end.
	for _, w := range []int{60, 40, 24} {
		m.width = w
		line := strings.TrimSpace(stripANSI(m.helpLines()))
		if lipglossWidth(line)+len(gutter) > w {
			t.Errorf("width %d: %q is too wide", w, line)
		}
		if !strings.HasPrefix(line, "↑↓ select") || !strings.HasSuffix(line, "q quit") {
			t.Errorf("width %d: lost an end of %q", w, line)
		}
		if !strings.Contains(line, "…") {
			t.Errorf("width %d: dropped keys without saying so: %q", w, line)
		}
	}
}

func TestNoRowIsWiderThanTheWindow(t *testing.T) {
	// A row that wraps makes the page taller than the terminal, and the
	// terminal scrolls to fit -- which takes the title off the top. Long log
	// lines are the ordinary case, not the corner.
	m := testModel()
	m.scr, m.logsLabel, m.logsOf, m.logsReady = screenLogs, "blog-web-1", "blog-web-1", true
	m.logs = strings.Repeat("x", 400) + "\n" + strings.Repeat("y", 400)
	m.width, m.height = 70, 12
	m.reflow()

	lines := strings.Split(stripANSI(m.View()), "\n")
	if len(lines) != m.height {
		t.Fatalf("rendered %d lines into %d", len(lines), m.height)
	}
	for i, ln := range lines {
		if w := lipglossWidth(ln); w > m.width {
			t.Errorf("row %d is %d columns wide, window is %d", i, w, m.width)
		}
	}

	// The monitor screen has the same obligation and is the likeliest to break
	// it: a chart is drawn to a width it computes rather than to whatever the
	// text happens to be, and the frame CLIPS rather than wraps -- so getting
	// this wrong silently cuts off the right-hand end, which is now.
	for _, w := range []int{60, 80, 120} {
		// With resource readings too: the bars are fixed-width and sit after a
		// padded label, so a narrow window is where they would push a row past
		// the edge and lose its right-hand end to the clip.
		c := sysModel("blog", "")
		c.monitorReady = true
		now := time.Now().Unix() / 60 * 60
		for i := 0; i < 120; i++ {
			c.monitor = append(c.monitor, metricRow{
				minute: now - int64(119-i)*60, app: "blog", c2: 10 + i, c5: i % 7})
		}
		c.width, c.height = w, 24
		c.reflow()
		cl := strings.Split(stripANSI(c.View()), "\n")
		if len(cl) != c.height {
			t.Errorf("the monitor at width %d: rendered %d lines into %d", w, len(cl), c.height)
		}
		for i, ln := range cl {
			if got := lipglossWidth(ln); got > c.width {
				t.Errorf("the monitor at width %d: row %d is %d columns", w, i, got)
			}
		}
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

	for _, k := range []focusKind{focusKomizo, focusProxy} {
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
		if next := send(m, "x"); next.scr != screenIndex {
			t.Errorf("%v: 'x' must do nothing with no app selected", k)
		}
		if next := send(m, "r"); next.scr != screenIndex {
			t.Errorf("%v: 'r' must do nothing with no app selected", k)
		}
	}
}
func TestTheProxyIsPlainRowsUnderServer(t *testing.T) {
	// One label/value row, the same shape as the komizo rows above it, with the
	// network on it rather than on a row of its own: the network is not a
	// thing anyone acts on, and its only interesting state is "missing".
	m := netModel()
	v := stripANSI(m.View())
	var proxyLn string
	for _, ln := range strings.Split(v, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "proxy") {
			proxyLn = ln
		}
	}
	if proxyLn == "" {
		t.Fatalf("the page is missing the proxy row:\n%s", v)
	}
	if !strings.Contains(proxyLn, "edge") {
		t.Errorf("the proxy row should carry the network: %q", proxyLn)
	}
	for _, ln := range strings.Split(v, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "network") {
			t.Errorf("the network must ride on the proxy row, not have one of its own: %q", ln)
		}
	}
	// No image row. It is the one fact here that cannot change without someone
	// deciding it should -- pinned by a flag on a command run once -- and this
	// page is for what is happening, not for confirming settings. `komizo list`
	// prints it, and reinstalling names it in the question.
	if strings.Contains(v, "caddy:2") {
		t.Error("the proxy image is not something this page reports")
	}

	// A box with no proxy has no image, and says so rather than showing blank.
	m.proxy = proxyRow{}
	if !strings.Contains(stripANSI(m.View()), "not installed") {
		t.Error("with no proxy the row should say so")
	}
}

func TestTheHostIsNamedWhereItMatters(t *testing.T) {
	// The header names the box, and only the box: the account is the same all
	// session and is not what tells two terminals apart, so a breadcrumb
	// carrying it spends width on a constant.
	m := testModel()
	v := stripANSI(m.View())
	if !strings.Contains(v, "box.example.com") {
		t.Error("the header should name the box")
	}
	if strings.Contains(v, "root@") {
		t.Error("the header should not carry the account")
	}

	// And anything destructive names the box itself regardless. A header is
	// read once and then stops being read, which is when it stops protecting
	// you -- so the most dangerous prompt in the program cannot lean on it.
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
	if m.scr != screenIndex {
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
	if m.scr != screenIndex {
		t.Error("and leave the list exactly where it was")
	}
}

func TestQuestionsNeverLeaveTheList(t *testing.T) {
	// The whole point: the row you are deciding about stays on screen.
	m := testModel()
	m.cursor = rowOf(m, focusApp)
	for _, k := range []string{"c", "r", "x", "p"} {
		next := send(m, k)
		if next.scr != screenIndex {
			t.Errorf("%q left the list for %v", k, next.scr)
		}
		if next.prompt == nil {
			t.Errorf("%q asked nothing", k)
		}
		if !strings.Contains(stripANSI(next.View()), "ghcr.io/you/blog-config") {
			t.Errorf("%q hid the list behind the question", k)
		}
	}
	// And the komizo row's update question behaves the same.
	m.cursor = rowOf(m, focusKomizo)
	if next := send(m, "u"); next.scr != screenIndex || next.prompt == nil {
		t.Error("updating komizo should ask in the footer too")
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

	// A page that overflows is SCROLLED, not spilled. It used to render in full
	// and let the terminal do the scrolling, and what a terminal scrolls off is
	// the top: the title went, then the Server section, and the keys ended up
	// wherever the last line landed.
	m.height = 12
	small := strings.Split(stripANSI(m.View()), "\n")
	if len(small) != 12 {
		t.Errorf("rendered %d lines into a 12-line terminal", len(small))
	}
	if !strings.Contains(small[0], "komizo") {
		t.Error("the title should survive a terminal too small for the page")
	}
	foot := rowsOf(stripANSI(m.pageFooter()))
	if got, want := small[len(small)-1], foot[len(foot)-1]; got != want {
		t.Errorf("bottom row is %q, want the footer's last line %q", got, want)
	}
}

func TestTheChromeRunsCornerToCorner(t *testing.T) {
	// The header and the footer are the window's edges. The gutter belongs to
	// the content between them -- indenting the chrome too put the title in
	// from the corner and left the rule short at both ends, so the page read as
	// a box floating inside the terminal rather than as the terminal.
	m := testModel()
	m.width, m.height = 70, 20
	m.cursor = rowOf(m, focusApp)
	m.status = "known_hosts copied"
	m.reflow()
	lines := strings.Split(stripANSI(m.View()), "\n")

	if strings.HasPrefix(lines[0], " ") {
		t.Errorf("the header should start in the corner, got %q", lines[0])
	}
	rule := ""
	for _, ln := range lines {
		if strings.HasPrefix(ln, "───") {
			rule = ln
		}
	}
	if lipglossWidth(rule) != m.width {
		t.Errorf("the rule is %d columns, want the full %d", lipglossWidth(rule), m.width)
	}
	// The status and the keys sit against the same margin as the rule.
	for _, want := range []string{"● known_hosts copied", "↑↓ select"} {
		found := false
		for _, ln := range lines {
			if strings.HasPrefix(ln, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q should be flush left in the footer:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	// The body keeps its gutter: content is indented, chrome is not.
	for _, ln := range lines {
		if strings.Contains(ln, "docker ") && !strings.HasPrefix(ln, gutter) {
			t.Errorf("a body row lost its gutter: %q", ln)
		}
	}
}

func TestFooterProseWrapsToTheWindow(t *testing.T) {
	// Rows are clipped to the window, so prose wrapped to a hard-coded 74 lost
	// its end in anything narrower.
	m := testModel()
	m.width, m.height = 62, 20
	m = openAddForm(m)
	m.reflow()

	v := stripANSI(m.View())
	if !strings.Contains(v, "another.") {
		t.Errorf("the last words of the detail were cut off:\n%s", v)
	}
	for _, ln := range strings.Split(v, "\n") {
		if lipglossWidth(ln) > m.width {
			t.Errorf("%q is wider than the window", ln)
		}
	}
}

// paste is what a terminal sends when text is pasted: one key message carrying
// every rune, rather than one message per character.
func paste(text string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text), Paste: true}
}

func TestEveryFieldTakesAPaste(t *testing.T) {
	// A paste is one key message with all the runes in it, and the test that
	// used to gate typing -- len(msg.String()) == 1 -- dropped it silently.
	// Every field was type-only, which is the wrong way round: an address or a
	// registry path is copied from a provider's console or a registry page.

	// The login field.
	login := newLoginModel()
	next, _ := login.Update(paste("root@box.example.com"))
	if got := next.(model).login; got != "root@box.example.com" {
		t.Errorf("login field has %q after a paste", got)
	}

	// The add form, which is three fields in the footer.
	form := openAddForm(testModel())
	next, _ = form.Update(paste("blog"))
	form = next.(model)
	form = send(form, "tab")
	next, _ = form.Update(paste("ghcr.io/you/blog-config"))
	form = next.(model)
	if form.form.app() != "blog" || form.form.config() != "ghcr.io/you/blog-config" {
		t.Errorf("form has %q / %q after pastes", form.form.app(), form.form.config())
	}

	// An editable value in the footer -- changing an app's config image.
	m := testModel()
	m.cursor = rowOf(m, focusApp)
	input := send(m, "c")
	if input.prompt == nil {
		t.Fatal("c should open an input")
	}
	next, _ = input.Update(paste("ghcr.io/you/other-config"))
	if got := next.(model).prompt.typed; !strings.HasSuffix(got, "other-config") {
		t.Errorf("input has %q after a paste", got)
	}

	// And the one that asks you to type a name to confirm.
	word := send(m, "x")
	next, _ = word.Update(paste("blog"))
	if got := next.(model).prompt.typed; got != "blog" {
		t.Errorf("confirmation has %q after a paste", got)
	}
}

func TestAPasteArrivesAsOneLine(t *testing.T) {
	// A value copied out of a terminal or a web page routinely brings a
	// trailing newline, and every field here is one line.
	m := newLoginModel()
	next, _ := m.Update(paste("root@box\n"))
	if got := next.(model).login; got != "root@box" {
		t.Errorf("login field has %q; the newline should not survive", got)
	}
	next, _ = m.Update(paste("a\tb\rc"))
	if got := next.(model).login; got != "abc" {
		t.Errorf("login field has %q; control characters should be dropped", got)
	}

	// Alt chords are not text: alt+a is a rune with the Alt flag, and inserting
	// "a" for it would put a letter in the field for a key nobody typed.
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a"), Alt: true})
	if got := next.(model).login; got != "" {
		t.Errorf("alt+a typed %q", got)
	}
}

func TestLoginAsksForAHost(t *testing.T) {
	// `komizo` on its own used to print the usage and exit 2, which made the
	// shortest thing anyone would type the one thing that did not work.
	m := newLoginModel()
	m.width, m.height = 64, 14
	m.reflow()

	v := stripANSI(m.View())
	for _, want := range []string{"komizo", tagline, "root@example.com", "connect"} {
		if !strings.Contains(v, want) {
			t.Errorf("the login screen should show %q:\n%s", want, v)
		}
	}
	// A placeholder, not a value: enter on an empty field does nothing.
	if next, cmd := m.Update(key("enter")); cmd != nil || next.(model).scr != screenLogin {
		t.Error("enter with nothing typed should do nothing")
	}

	typed := send(m, "r", "o", "o", "t", "@", "b", "o", "x")
	if typed.login != "root@box" {
		t.Errorf("typed %q, want root@box", typed.login)
	}
	if !strings.Contains(stripANSI(typed.View()), "root@box") {
		t.Error("the field should show what was typed")
	}
	if back := send(typed, "backspace"); back.login != "root@bo" {
		t.Errorf("backspace left %q", back.login)
	}

	// A bad address is refused before any connection is attempted, and the
	// text stays in the field to be fixed.
	bad := send(m, "r", "o", "o", "t", "@", "b", "a", "d", " ", "x")
	next, cmd := bad.Update(key("enter"))
	if cmd != nil {
		t.Error("a malformed address should not open a connection")
	}
	after := next.(model)
	if after.scr != screenLogin || after.login == "" || !after.statusErr {
		t.Errorf("expected the field kept and an error shown, got %q / %v", after.login, after.status)
	}
}

func TestTheSpinnerTurnsOnEveryPathIntoLoading(t *testing.T) {
	// The ticker stops when nothing needs it, so every way into a state that
	// animates has to start it again. From the login screen nothing was
	// spinning, so the first tick after startup killed the ticker and the
	// connect that followed showed a spinner frozen on its first frame -- while
	// the same code worked from the command line, where the model starts on the
	// loading screen with the ticker already alive.
	//
	// Tested through beginLoading rather than by running what the key handlers
	// return: those batches carry the connect, and running one opens a real SSH
	// connection and waits out its timeout.
	sentinel := func() tea.Msg { return appsMsg{} }
	spins := func(cmd tea.Cmd) bool {
		batch, ok := cmd().(tea.BatchMsg)
		if !ok {
			return false // not a batch: the sentinel came back on its own
		}
		for _, c := range batch {
			if _, isSpin := c().(spinMsg); isSpin {
				return true
			}
		}
		return false
	}

	idle := newLoginModel()
	if !spins(idle.beginLoading(sentinel)) {
		t.Error("loading from a screen with nothing animating should start the spinner")
	}
	if idle.scr != screenLoading {
		t.Errorf("beginLoading should land on the loading screen, got %v", idle.scr)
	}

	// Already spinning: no second ticker, or the animation runs at double speed.
	busy := newLoginModel()
	busy.busy = map[string]bool{"app:blog": true}
	if spins(busy.beginLoading(sentinel)) {
		t.Error("a second ticker should not be started on top of a live one")
	}

	// And the state keeps it alive once it is running.
	if !idle.spinning() {
		t.Error("the loading screen should keep the spinner animating")
	}

	// The login screen itself has nothing to animate, so Init must not start a
	// ticker there -- it would die on its first tick and take the next one with
	// it, which is the whole bug.
	if newLoginModel().spinning() {
		t.Error("the login screen has nothing to spin")
	}

	// Connecting goes through it: the screen changes and work is returned.
	m := newLoginModel()
	m.login = "root@box"
	next, cmd := m.Update(key("enter"))
	if cmd == nil || next.(model).scr != screenLoading {
		t.Error("enter on a valid address should start connecting")
	}
}

func TestAnUnreachableHostComesBackToTheField(t *testing.T) {
	// Everything here is recoverable by typing something else, so a failure
	// returns to the field with the address still in it.
	m := newLoginModel()
	m.width, m.height = 64, 14
	m.login, m.scr = "root@box", screenLoading

	tgt, _ := parseTarget("root@box")
	next, _ := m.Update(connectMsg{tgt: tgt, res: reachResult{kind: reachNetwork}})
	after := next.(model)
	if after.scr != screenLogin {
		t.Errorf("a failed connection should return to the login screen, got %v", after.scr)
	}
	if after.login != "root@box" {
		t.Errorf("the address should still be in the field, got %q", after.login)
	}
	if !after.statusErr || !strings.Contains(after.status, "box") {
		t.Errorf("the reason should name the host, got %q", after.status)
	}

	// A host nobody has met asks rather than failing -- with its fingerprints
	// beside the question, which is the only reason the question is answerable.
	unseen := connectMsg{tgt: tgt, res: reachResult{kind: reachUnknownHost},
		scan: []byte("box ssh-ed25519 AAAA\n"), fp: []string{"256 SHA256:abc box (ED25519)"}}
	next, _ = m.Update(unseen)
	asked := next.(model)
	if asked.prompt == nil || !strings.Contains(asked.prompt.question, "Trust") {
		t.Fatal("an unseen host key should be asked about, not refused")
	}
	if !strings.Contains(asked.prompt.detail, "SHA256:abc") {
		t.Error("the fingerprints should be on screen while the question is asked")
	}
}

// The two waits share a spinner and differ in everything around it.
//
// The first read has nothing to say yet -- no host, no screen behind it -- so
// it is the name in the middle of an empty page. A log that has not arrived has
// a header that already says whose log it is, which is the one thing worth
// knowing while it loads, so it keeps that and shows the spinner alone.
func TestWaitsShowASpinner(t *testing.T) {
	first := testModel()
	first.width, first.height = 60, 12
	first.scr = screenLoading

	log := testModel()
	log.width, log.height = 60, 12
	log.scr, log.logsOf, log.logsLabel, log.logsReady = screenLogs, "web", "web", false

	for name, m := range map[string]model{"the first read": first, "opening a log": log} {
		m.reflow()
		v := stripANSI(m.View())
		if !strings.Contains(v, stripANSI(spinner(m.spin))) {
			t.Errorf("%s: the spinner should be on screen", name)
		}
	}

	// Centred, and the only one on the page: the loading screen stands its
	// header down, because the pane is already the name.
	first.reflow()
	fv := stripANSI(first.View())
	names := 0
	for _, ln := range strings.Split(fv, "\n") {
		if strings.TrimSpace(ln) != "komizo" {
			continue
		}
		names++
		if !strings.HasPrefix(ln, "          ") {
			t.Errorf("the name should be centred, got %q", ln)
		}
	}
	if names != 1 {
		t.Errorf("the first read shows the name %d times, want once", names)
	}

	// The log keeps its header, so the middle is the spinner and a word for
	// what it is doing -- and NOT the name, which the corner already carries.
	log.reflow()
	lv := stripANSI(log.View())
	if !strings.Contains(lv, "komizo / box.example.com / web / logs") {
		t.Errorf("a loading log should keep its header:\n%s", lv)
	}
	if !strings.Contains(lv, "loading...") {
		t.Errorf("a loading log should say so under the spinner:\n%s", lv)
	}
	if strings.Contains(lv, tagline) {
		t.Errorf("a loading log should not carry the brand block:\n%s", lv)
	}
	for _, ln := range strings.Split(lv, "\n") {
		if strings.TrimSpace(ln) == "komizo" {
			t.Errorf("the name should appear only in the header, got %q", ln)
		}
	}

	// And the spinner has to be turning: the ticker runs from the first frame,
	// because the loading pane is the first thing on screen.
	if !first.spinning() {
		t.Error("the loading screen should keep the spinner animating")
	}
	if cmds := testModel().Init(); cmds == nil {
		t.Error("Init should start the spinner ticking")
	}
}

func TestTheHeaderSaysWhereYouAre(t *testing.T) {
	// komizo / root@box / astry / api / logs: the tool, which box, and where in
	// it. The brand keeps the accent and the bold; the crumbs are plain, so the
	// eye lands on the tool first and the parts that change read as the parts
	// that change.
	//
	// The index has no crumb of its own. It is the page the tool opens on, not
	// somewhere you navigated to, and a word after the host would only be a
	// name for "here".
	//
	// The address is a crumb rather than a row in the Server section because it
	// is not a property of the box the way its docker version is -- it is WHICH
	// box, and every other fact on the page is relative to it.
	m := testModel()
	m.width, m.height = 90, 20

	// Only the pages that carry the name in the middle -- login, loading and
	// setup -- stand the header down, because their body is already the name.
	// A log keeps its header whether or not it has arrived. See showsBrand.
	for name, c := range map[string]struct {
		set  func(*model)
		want string
	}{
		"the index": {func(m *model) {}, "komizo / box.example.com"},
		"a log": {func(m *model) {
			m.scr, m.logsLabel, m.logsOf, m.logsReady = screenLogs, "blog-web-1", "x", true
			m.logsApp, m.logsSvc = "blog", "blog-web-1"
			m.logs = "one\ntwo"
		}, "komizo / box.example.com / blog / blog-web-1 / logs"},
	} {
		next := m
		c.set(&next)
		next.reflow()
		lines := strings.Split(stripANSI(next.View()), "\n")
		if got := strings.TrimSpace(lines[0]); got != c.want {
			t.Errorf("%s: header is %q, want %q", name, got, c.want)
		}
	}

	// The log window's title was the first line of its body, so reading to the
	// bottom of a long log left a screen of untitled output. Up here it cannot
	// scroll away.
	l := m
	l.scr, l.logsLabel, l.logsOf, l.logsReady = screenLogs, "blog-web-1", "x", true
	l.logsApp, l.logsSvc = "blog", "blog-web-1"
	l.logs = strings.Repeat("a line\n", 200)
	l.scroll = 999
	l.reflow()
	if !strings.Contains(stripANSI(l.View()), "blog-web-1 / logs") {
		t.Error("the crumb should survive scrolling to the end of a log")
	}
}

func TestEveryScreenIsFramed(t *testing.T) {
	// The frame is the point: whatever is on screen, the title is on top, the
	// keys are on the bottom row, and the page is exactly the height of the
	// terminal. Every screen, at a size too small for any of them, because the
	// size that fits is the one that never showed the bug.
	base := testModel()
	base.width, base.height = 80, 14

	logs := base
	logs.scr, logs.logsLabel, logs.logsOf, logs.logsReady = screenLogs, "blog-web-1", "blog-web-1", true
	logs.logs = strings.Repeat("a log line\n", 40)

	run := base
	run.startOp("Setting up box.example.com")

	done := showResult(base, &addResult{app: "blog", keyPath: "/k", knownHosts: "h k b"})

	form := base
	form.form = newAddForm(base.tgt)
	form.prompt = &prompt{kind: promptForm, question: "Add an app"}

	init := base
	init.scr = screenSetup

	for name, m := range map[string]model{
		"list": base, "logs": logs, "running": run,
		"result": done, "form": form, "init": init,
	} {
		m.reflow()
		lines := strings.Split(stripANSI(m.View()), "\n")
		if len(lines) != m.height {
			t.Errorf("%s: %d lines in a %d-line terminal", name, len(lines), m.height)
			continue
		}
		// Either the header names the page, or the body centres the name.
		if !strings.Contains(strings.Join(lines, "\n"), "komizo") {
			t.Errorf("%s: the name is nowhere on the page", name)
		}
		foot := rowsOf(stripANSI(m.pageFooter()))
		if got, want := lines[len(lines)-1], foot[len(foot)-1]; got != want {
			t.Errorf("%s: bottom row is %q, want %q", name, got, want)
		}
	}
}

func TestScrollingNeverMovesTheSelection(t *testing.T) {
	// The page scrolls to keep the selected row visible. The reverse must not
	// happen: nothing about where the page sits may change WHICH row is
	// selected, or the keys in the footer would act on a row you never chose.
	// Up and down are the only two keys that move it.
	m := testModel()
	one := m.apps[0]
	for i := 0; i < 30; i++ {
		a := one
		a.name = fmt.Sprintf("app%02d", i)
		m.apps = append(m.apps, a)
	}
	m.width, m.height = 90, 16
	m.cursor = 8
	m.reflow()
	was := m.cursor

	// A resize re-lays out the whole page, and a refresh replaces every row.
	for _, h := range []int{40, 10, 24} {
		next, _ := m.Update(tea.WindowSizeMsg{Width: 90, Height: h})
		m = next.(model)
		if m.cursor != was {
			t.Errorf("resizing to %d lines moved the selection %d -> %d", h, was, m.cursor)
		}
	}
	// And the five-second poll, which happens whether or not anyone is here.
	next, _ := m.Update(pollMsg{})
	if got := next.(model).cursor; got != was {
		t.Errorf("the poll moved the selection %d -> %d", was, got)
	}

	for _, k := range []string{"g", "G", "pgup", "pgdown", " ", "f", "b", "c", "l", "p"} {
		if got := send(m, k).cursor; got != was {
			t.Errorf("%q moved the selection %d -> %d", k, was, got)
		}
	}
	if got := send(m, "down").cursor; got != was+1 {
		t.Errorf("down should move the selection, got %d", got)
	}
	if got := send(m, "up").cursor; got != was-1 {
		t.Errorf("up should move the selection, got %d", got)
	}
}

func TestTheCursorStaysOnScreen(t *testing.T) {
	// Thirty apps in a window with room for a handful of rows. Whichever one is
	// selected has to be visible: a cursor you cannot see is a cursor you cannot
	// use, and the keys in the footer act on it.
	m := testModel()
	one := m.apps[0]
	for i := 0; i < 30; i++ {
		a := one
		a.name = fmt.Sprintf("app%02d", i)
		m.apps = append(m.apps, a)
	}
	m.width, m.height = 90, 20

	for _, c := range []int{0, 5, 12, len(m.focusItems()) - 1, 3} {
		m.cursor = c
		m.reflow()
		v := stripANSI(m.View())
		if n := len(strings.Split(v, "\n")); n != m.height {
			t.Fatalf("cursor %d: rendered %d lines into %d", c, n, m.height)
		}
		if anchorOf(strings.Split(m.View(), "\n")) < 0 {
			t.Errorf("cursor %d is off screen", c)
		}
	}
}

func TestStartStopAsksFirst(t *testing.T) {
	m := testModel()
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 2 days"},
	}

	for _, k := range []focusKind{focusProxy, focusApp, focusContainer} {
		m.cursor = rowOf(m, k)
		next := send(m, "s")
		if next.prompt == nil {
			t.Fatalf("%v: s should ask before starting or stopping", k)
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
	if q := send(m, "s").prompt; !strings.Contains(q.detail, "blog.example.com") {
		t.Errorf("the question should name the hostnames that stop answering: %q", q.detail)
	}
}

func TestTheMonitorHasNoHeadings(t *testing.T) {
	// The page carries no section labels at all. Server, Proxy and Apps each
	// named a handful of rows whose shape already said what they were -- flat
	// label/value rows for the box, a tree for the apps -- so each heading cost
	// a line to repeat what was under it. The blank lines between them stayed;
	// that was the part doing the work.
	v := stripANSI(testModel().View())
	for _, gone := range []string{"Server", "Proxy", "Apps"} {
		if strings.Contains(v, gone) {
			t.Errorf("the page should have no %q heading:\n%s", gone, v)
		}
	}
	// The tool's name is still on it, in the header.
	if !strings.Contains(v, "komizo") {
		t.Error("the header should still name the tool")
	}
	// Order still matters: what the box IS -- os, the komizo it was set up with --
	// then the proxy every request passes through, then the apps.
	iOS := strings.Index(v, "alpine")
	iK := strings.Index(v, "komizo server")
	iP := strings.Index(v, "proxy")
	iA := strings.Index(v, "blog")
	if !(iOS < iK && iK < iP && iP < iA) {
		t.Errorf("rows out of order: os=%d komizo=%d proxy=%d apps=%d", iOS, iK, iP, iA)
	}
	// Named "proxy" rather than "status": with no heading over it, "status"
	// would read as the server's status, which is a different claim.
	if strings.Contains(v, "status") {
		t.Error(`the proxy row should be labelled "proxy", not "status"`)
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
	m = send(m, "s", "y")
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

func TestThePollSkipsWhenItWouldHurt(t *testing.T) {
	// The poll is only ever right on the list, idle. Everywhere else it is a
	// connection nobody asked for, and in two of these cases its answer would
	// visibly break the page.
	for name, mutate := range map[string]func(*model){
		"reading a log":  func(m *model) { m.scr = screenLogs },
		"already asking": func(m *model) { m.fetching = true },
		"a row is busy":  func(m *model) { m.busy = map[string]bool{"app:blog": true} },
		"a row settling": func(m *model) { m.settling = map[string]bool{"app:blog": true} },
	} {
		m := testModel()
		mutate(&m)
		if cmd := m.poll(); cmd != nil {
			t.Errorf("%s: should not have polled", name)
		}
	}

	m := testModel()
	if cmd := m.poll(); cmd == nil {
		t.Error("an idle list should poll")
	} else if !m.fetching {
		t.Error("a poll in flight should be recorded, or the next tick stacks another")
	}

	// An open question does NOT stop it. The list behind the question is the
	// reason the question is in the footer, and one that stops updating the
	// moment you start deciding is stale exactly when you are looking hardest.
	for name, mutate := range map[string]func(*model){
		"a confirmation": func(m *model) { m.prompt = &prompt{kind: promptConfirm} },
		"the add form":   func(m *model) { *m = openAddForm(*m) },
		"mid-operation":  func(m *model) { m.startOp("Setting up blog") },
		"a result shown": func(m *model) {
			*m = showResult(*m, &addResult{app: "blog", keyPath: "/k"})
		},
	} {
		m := testModel()
		mutate(&m)
		if cmd := m.poll(); cmd == nil {
			t.Errorf("%s: the list behind it should keep updating", name)
		}
	}
}

func TestAFailedPollKeepsThePage(t *testing.T) {
	// One dropped connection must not blank a working list. The error comes
	// back with an empty inventory, and taking it would replace every row --
	// then the next poll five seconds later would put them all back.
	m := testModel()
	m.loaded = true
	had := len(m.apps)

	next, _ := m.Update(appsMsg{err: fmt.Errorf("connection refused")})
	after := next.(model)
	if len(after.apps) != had {
		t.Errorf("a failed poll emptied the list: %d apps, want %d", len(after.apps), had)
	}
	if after.err == nil {
		t.Error("a failed poll should still say so")
	}
	if after.fetching {
		t.Error("a failed poll must clear the in-flight flag, or polling stops for good")
	}
	// And the next good read clears it again.
	next, _ = after.Update(appsMsg{apps: m.apps, srv: m.srv, proxy: m.proxy})
	if next.(model).err != nil {
		t.Error("a good read should clear the error")
	}
}

func TestAPollDoesNotMoveYouBetweenScreens(t *testing.T) {
	// appsMsg used to set the screen unconditionally, which was harmless when
	// the only way to trigger one was pressing R on the list. A poll arriving
	// every five seconds would now throw you out of whatever you were reading.
	for _, scr := range []screen{screenLogs, screenMonitor} {
		m := testModel()
		m.loaded, m.scr = true, scr
		next, _ := m.Update(appsMsg{apps: m.apps, srv: m.srv, proxy: m.proxy})
		if got := next.(model).scr; got != scr {
			t.Errorf("a poll moved the screen %v -> %v", scr, got)
		}
	}
	// From the loading screen it is the thing that decides where to go.
	m := testModel()
	m.scr = screenLoading
	next, _ := m.Update(appsMsg{apps: m.apps, srv: m.srv, proxy: m.proxy})
	if got := next.(model).scr; got != screenIndex {
		t.Errorf("the first read should land on the list, got %v", got)
	}
}

func TestThePollKeepsTicking(t *testing.T) {
	// The tick carries no data and changes nothing on the page: it asks for a
	// read, and the answer arrives later as an appsMsg.
	m := netModel()
	before := m
	next, cmd := m.Update(pollMsg{})
	if cmd == nil {
		t.Fatal("the poll should keep ticking")
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
			// And the window still says which log it is -- unless it is still
			// arriving, where the page is the centred name and the spinner.
			want := "x / logs"
			if !loaded {
				want = "komizo"
			}
			if !strings.Contains(v, want) {
				t.Errorf("height=%d loaded=%v: %q is missing", h, loaded, want)
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
	if !strings.Contains(stripANSI(m.View()), stripANSI(spinner(m.spin))) {
		t.Error("a loading log should show the spinner")
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

func TestTheImageColumnDropsTheVersionItRepeats(t *testing.T) {
	// Every service is pinned to ${APP_VERSION}, so the tag is the commit SHA
	// already shown on the app's row -- sixty characters of column saying what
	// the row above said. The registry and namespace go too: they are the same
	// for every image in the app, so they are a wall with the answer after it.
	c := containerRow{image: "ghcr.io/you/blog-api:a1b2c3d4e5f6"}
	if got := c.imageText("a1b2c3d4e5f6"); got != "blog-api" {
		t.Errorf("imageText = %q, want the name alone", got)
	}
	// A tag that is NOT the version is the interesting case: a service left on
	// :latest, or an upstream image. That tag survives.
	if got := c.imageText("deadbeef"); got != "blog-api:a1b2c3d4e5f6" {
		t.Errorf("a tag that is not the version should survive, got %q", got)
	}
	if got := (containerRow{image: "caddy:2"}).imageText("a1b2c3d"); got != "caddy:2" {
		t.Errorf("an upstream image should be shown as it is, got %q", got)
	}
	// An app that has never deployed has no version to compare against, so the
	// tag stays -- but the registry is noise either way.
	if got := c.imageText("none"); got != "blog-api:a1b2c3d4e5f6" {
		t.Errorf("with no version the tag is shown whole, got %q", got)
	}
	// A registry with a port has a colon that is not a tag separator. Cutting
	// the tag first and the path second is what keeps them apart.
	if got := (containerRow{image: "localhost:5000/api:v3"}).imageText("v3"); got != "api" {
		t.Errorf("a registry port is not a tag, got %q", got)
	}
	if got := (containerRow{image: "localhost:5000/api"}).imageText("none"); got != "api" {
		t.Errorf("an untagged image on a ported registry, got %q", got)
	}
}

// An app declares hostnames; komizo routes them to that app's gate and shows
// them on the row of the container actually serving them.
//
// This is the whole of what the tool can now say about routing, and saying less
// than before is the point: what a request meets after the gate is inside the
// app, in config komizo neither writes nor reads.
func TestHostnamesLandOnTheGatewayRow(t *testing.T) {
	out := strings.Join([]string{
		"server\tready\tDocker version 26.1.3",
		"app\tblog\tkomizo-blog\t/srv/blog\ta1b2c3d\t2\tghcr.io/you/blog-config\t",
		"container\tblog\tblog-gate\tblog-blog-gate-1\trunning\tUp 3 hours\t2026-07-28T09:00:00Z\t0001-01-01T00:00:00Z\t0\tghcr.io/you/blog-gate:a1b2c3d\t80",
		"container\tblog\tblog-api\tblog-blog-api-1\trunning\tUp 3 hours\t2026-07-28T09:00:00Z\t0001-01-01T00:00:00Z\t0\tghcr.io/you/blog-api:a1b2c3d\t9090",
		"route\tblog\tblog.example.com,www.blog.example.com\tblog-gate\t80",
	}, "\n")

	apps, _, _, _, _ := parseInventory(out)
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}
	// One record for the app, not one per hostname: the app publishes a list.
	if n := len(apps[0].routes); n != 1 {
		t.Fatalf("expected 1 route record, got %d", n)
	}
	if got := apps[0].allRoutes(); len(got) != 2 {
		t.Errorf("allRoutes() = %q, want both names", got)
	}

	byContainer := apps[0].routesByContainer(netRow{})
	if got := byContainer["blog-blog-gate-1"]; len(got) != 2 {
		t.Errorf("the gate should carry both hostnames, got %q", got)
	}
	// And nothing else does. The API is behind the gate now; a hostname on
	// its row would claim the shared proxy reaches it, which it no longer can.
	if got := byContainer["blog-blog-api-1"]; len(got) != 0 {
		t.Errorf("a service behind the gate should carry no hostnames, got %q", got)
	}

	m := testModel()
	m.width, m.height = 120, 30
	m.apps = apps
	v := stripANSI(m.View())
	if !strings.Contains(v, "blog.example.com") {
		t.Errorf("the hostnames should be on screen:\n%s", v)
	}
	// The port is observed from the container's own namespace, so it is there
	// for every running container -- including the ones behind the gate,
	// which publish nothing and are named by no route.
	if !strings.Contains(v, ":80") {
		t.Errorf("the gate's listening port should be on screen:\n%s", v)
	}
	if !strings.Contains(v, ":9090") {
		t.Errorf("a service behind the gate still shows what it listens on:\n%s", v)
	}
}

// A container's listening ports are observed, not declared -- so they are there
// for services nothing routes to, and absent for a container with no network
// namespace to read.
func TestPortsAreObservedPerContainer(t *testing.T) {
	out := strings.Join([]string{
		"server\tready\tDocker version 26.1.3",
		"app\tblog\tkomizo-blog\t/srv/blog\ta1b2c3d\t2\tghcr.io/you/blog-config\t",
		"container\tblog\tblog-gate\tblog-gw-1\trunning\tUp 3 hours\t2026-07-28T09:00:00Z\t0001-01-01T00:00:00Z\t0\tghcr.io/you/blog-gate:a1b2c3d\t80",
		"container\tblog\tblog-worker\tblog-worker-1\trunning\tUp 3 hours\t2026-07-28T09:00:00Z\t0001-01-01T00:00:00Z\t0\tghcr.io/you/blog-worker:a1b2c3d\t",
		"container\tblog\tblog-db\tblog-db-1\trunning\tUp 3 hours\t2026-07-28T09:00:00Z\t0001-01-01T00:00:00Z\t0\tghcr.io/you/blog-db:a1b2c3d\t5432,9187",
		"route\tblog\tblog.example.com\tblog-gate\t80",
	}, "\n")
	apps, _, _, _, _ := parseInventory(out)
	byName := map[string]containerRow{}
	for _, c := range apps[0].containers {
		byName[c.name] = c
	}

	if got := byName["blog-gw-1"].portsText(); got != ":80" {
		t.Errorf("gate port = %q, want \":80\"", got)
	}
	// Several listeners are all shown: a database and its exporter is a normal
	// shape, and picking one of them would be picking arbitrarily.
	if got := byName["blog-db-1"].portsText(); got != ":5432, :9187" {
		t.Errorf("multi-port = %q, want \":5432, :9187\"", got)
	}
	// A worker binds nothing. An em dash, not blank -- blank reads as a column
	// that failed to load.
	if got := byName["blog-worker-1"].portsText(); got != "—" {
		t.Errorf("a worker that listens on nothing = %q, want an em dash", got)
	}

	m := testModel()
	m.width, m.height = 120, 30
	m.apps = apps
	v := stripANSI(m.View())
	// The database is behind the gate and no route names it, but its port is
	// still known -- which is the whole point of observing rather than parsing
	// what the proxy was told to dial.
	if !strings.Contains(v, ":5432") {
		t.Errorf("a container no route names should still show its port:\n%s", v)
	}
}

// Request counts are read off the proxy's access log and attributed to apps by
// hostname. The join is the part most likely to be silently wrong, so it is what
// this pins.
func TestMetricsParseAndAttribute(t *testing.T) {
	out := strings.Join([]string{
		"app\tblog\tkomizo-blog\t/srv/blog\ta1b2c3d\t1\tghcr.io/you/blog-config\t",
		"metric\t1785225600\tblog\t\t10\t1\t2\t3",
		"metric\t1785225660\tblog\tapi\t20\t0\t0\t0",
		"metric\t1785225660\tshop\t\t5\t0\t0\t0",
		"garbage that is not a record",
		"metric\tnotanumber\tblog\t\t1\t1\t1\t1",
	}, "\n")

	rows := parseMetrics(out)
	if len(rows) != 3 {
		t.Fatalf("expected 3 metric rows, got %d: %+v", len(rows), rows)
	}
	// Sorted by minute then app, so a chart can walk them in order.
	if rows[0].minute != 1785225600 || rows[0].app != "blog" {
		t.Errorf("first row = %+v", rows[0])
	}
	if got := rows[0].total(); got != 16 {
		t.Errorf("total = %d, want 10+1+2+3", got)
	}

	// One app's series never picks up another's counts.
	s := seriesFor(rows, "blog", 1785225600, 1785225660)
	if len(s.total) != 2 {
		t.Fatalf("expected 2 minutes, got %d", len(s.total))
	}
	if s.total[0] != 16 || s.total[1] != 20 {
		t.Errorf("blog totals = %v, want [16 20]", s.total)
	}
	if s.errors[0] != 3 || s.errors[1] != 0 {
		t.Errorf("blog 5xx = %v, want [3 0]", s.errors)
	}
}

// A minute with no traffic produces no record -- there is nothing to count. It
// has to chart as zero, because a missing point draws a line straight across the
// gap, and the gap is the outage.
func TestQuietMinutesChartAsZeroNotAsAGap(t *testing.T) {
	rows := []metricRow{
		{minute: 600, app: "blog", c2: 9},
		{minute: 780, app: "blog", c2: 4}, // 600, [nothing], [nothing], 780
	}
	s := seriesFor(rows, "blog", 600, 780)
	if len(s.total) != 4 {
		t.Fatalf("expected 4 minutes, got %d", len(s.total))
	}
	if s.total[0] != 9 || s.total[1] != 0 || s.total[2] != 0 || s.total[3] != 4 {
		t.Errorf("series = %v, want [9 0 0 4]", s.total)
	}
}

// Downsampling averages rather than samples: picking every kth minute drops the
// spike that is the whole reason anyone looked.
func TestBucketingKeepsSpikes(t *testing.T) {
	v := make([]float64, 40)
	v[17] = 100
	out := bucketTo(v, 8)
	if len(out) != 8 {
		t.Fatalf("want 8 buckets, got %d", len(out))
	}
	var sum float64
	for _, x := range out {
		sum += x
	}
	if sum == 0 {
		t.Error("the spike vanished; downsampling must average, not sample")
	}
}

// A processor rate needs a PAIR of readings and the poll interval is five
// seconds -- without a quick second reading the bar is missing exactly while
// the page is being looked at hardest.
func TestTheFirstSampleSchedulesAQuickSecondReading(t *testing.T) {
	m := testModel()
	next, cmd := m.Update(appsMsg{apps: m.apps, srv: m.srv, proxy: m.proxy, net: m.net,
		sys: parseSystem("sys\tcpu\t100000\t90000\n", time.Unix(1000, 0))})
	if cmd == nil {
		t.Fatal("the first sample should schedule a follow-up reading")
	}
	// Only the first. Once a pair exists the ordinary cadence is enough, and an
	// extra tick per poll would compound into polling the box twice as often.
	if _, cmd = next.Update(appsMsg{apps: m.apps, srv: m.srv, proxy: m.proxy, net: m.net,
		sys: parseSystem("sys\tcpu\t200000\t180000\n", time.Unix(1005, 0))}); cmd != nil {
		t.Error("a later sample should not schedule extra polls")
	}
}

// brailleInk reports whether any braille dot is drawn inside a rectangle of a
// rendered chart, in character cells: lines y0..y1 of the view, columns x0..x1.
// The blank braille cell U+2800 is not ink.
func brailleInk(view string, x0, x1, y0, y1 int) bool {
	lines := strings.Split(view, "\n")
	for y := y0; y <= y1 && y < len(lines); y++ {
		x := 0
		for _, r := range lines[y] {
			if x > x1 {
				break
			}
			if x >= x0 && r > '⠀' && r <= '⣿' {
				return true
			}
			x++
		}
	}
	return false
}

// Two separate excursions must not be joined. ntcharts draws a line from every
// point in a data set to the point pushed after it, whatever lies between --
// an earlier form of this chart fed disjoint stretches of the score into one
// data set and ruled a chord from the end of one episode straight across the
// chart to the start of the next, through an hour that was fine.
func TestSeparateExcursionsAreNotJoinedByAChord(t *testing.T) {
	const n = 120
	from := int64(1_700_000_000) / 60 * 60
	times := minuteTimes(from, n)
	// Three minutes each, so the median-of-three in quietened keeps them, both
	// at the ceiling.
	score := make([]float64, n)
	score[20], score[21], score[22] = 5, 5, 5
	score[100], score[101], score[102] = 5, 5, 5
	view := model{}.sigmaChart(timeRange{from: from, to: from + (n-1)*60},
		times, baseline{score: score}, 80, 12)
	// The stretch between the episodes, above the reference line. The score is
	// flat normal there, so the line belongs at half height; a chord from the
	// first episode's ceiling would cross the top rows of these columns.
	if brailleInk(view, 30, 48, 0, 3) {
		t.Errorf("ink between two separate excursions; the episodes are being joined by a chord:\n%s", view)
	}
}

// A stretch with no score is a statement -- "we cannot say" -- and the line
// must break across it, not bridge it. The gap here is flanked by lifted
// scores: a bridge at that height is visible ink, where a bridge at exactly
// normal would hide along the reference line.
func TestTheScoreLineBreaksWhereNothingWasScored(t *testing.T) {
	const n = 120
	from := int64(1_700_000_000) / 60 * 60
	times := minuteTimes(from, n)
	score := make([]float64, n)
	for i := 20; i < 40; i++ {
		score[i] = 3 // past the dead zone: lifted to three quarters height
	}
	for i := 40; i < 80; i++ {
		score[i] = math.NaN()
	}
	for i := 80; i < 103; i++ {
		score[i] = 3
	}
	view := model{}.sigmaChart(timeRange{from: from, to: from + (n-1)*60},
		times, baseline{score: score}, 80, 12)
	// Inside the unscored stretch nothing sits in the upper rows: the
	// reference line is at half height and nothing was scored here. Ink up
	// there is the lifted line either side being joined across the gap.
	if brailleInk(view, 35, 50, 0, 3) {
		t.Errorf("ink across an unscored stretch; the score line must break there:\n%s", view)
	}
}

// Enter opens the monitor for whatever is selected.
func TestEnterOpensTheMonitor(t *testing.T) {
	m := netModel()
	m.width, m.height = 100, 30
	m.cursor = rowOf(m, focusApp)
	next, cmd := sendCmd(m, "enter")
	if next.scr != screenMonitor {
		t.Fatalf("enter on an app should open the monitor, got %v", next.scr)
	}
	if cmd == nil {
		t.Error("it should fetch the counts")
	}
	if next.monitorOf != m.apps[0].name {
		t.Errorf("the monitor is for %q, want %q", next.monitorOf, m.apps[0].name)
	}
	if next.monitorReady {
		t.Error("it should not claim to be ready before the fetch lands")
	}
	if back := send(next, "esc"); back.scr != screenIndex {
		t.Error("esc should go back to the list")
	}

	// The proxy row opens the whole box: every request to every app passes
	// through it, and it is the only row that can be asked about all of them.
	p := netModel()
	p.width, p.height = 100, 30
	p.cursor = rowOf(p, focusProxy)
	box, cmd := sendCmd(p, "enter")
	if box.scr != screenMonitor {
		t.Fatalf("enter on the proxy should open the box's requests, got %v", box.scr)
	}
	if cmd == nil {
		t.Error("it should fetch")
	}
	if box.monitorOf != "" || box.monitorSvc != "" {
		t.Errorf("the box's chart names no app: got %q/%q", box.monitorOf, box.monitorSvc)
	}
	// Its crumb nests under nothing -- the host in front of it already names
	// the machine.
	if got := box.crumb(); got != "monitor" {
		t.Errorf("box crumb = %q, want \"monitor\"", got)
	}
}

// A late fetch for one app must not land over another's, the same guard the log
// window needs.
func TestALateChartFetchIsIgnored(t *testing.T) {
	m := netModel()
	m.monitorOf, m.monitorReady = "blog", false
	next, _ := m.Update(monitorMsg{app: "shop", rows: []metricRow{{minute: 60, app: "shop", c2: 1}}})
	m = next.(model)
	if m.monitorReady || len(m.monitor) != 0 {
		t.Error("a chart for another app should be dropped, not shown")
	}
	next, _ = m.Update(monitorMsg{app: "blog", rows: []metricRow{{minute: 60, app: "blog", c2: 1}}})
	m = next.(model)
	if !m.monitorReady || len(m.monitor) != 1 {
		t.Error("the one that was asked for should land")
	}
}

// The baseline is trailing: each minute is measured against the minutes BEFORE
// it and nothing after. That is what makes a point's score final once computed --
// a whole-window average puts an incident inside its own baseline and silently
// moves every past point as new data arrives.
func TestBaselineOnlyLooksBackwards(t *testing.T) {
	v := make([]float64, baselineWindow+4)
	for i := range v {
		v[i] = 10
	}
	// A spike at the very end must not have coloured the scores before it.
	v[len(v)-1] = 500

	b := trailingBaseline(v)

	// No baseline until there is enough history. Not zero -- "we cannot say" and
	// "exactly normal" must not share a shape.
	for i := 0; i < baselineWindow; i++ {
		if !math.IsNaN(b.score[i]) {
			t.Fatalf("minute %d scored with no baseline: %v", i, b.score[i])
		}
	}
	// The steady minutes read as ordinary...
	steady := b.score[baselineWindow]
	if !math.IsNaN(steady) && math.Abs(steady) > 0.001 {
		t.Errorf("a flat run should score ~0, got %v", steady)
	}
	// ...and the spike is the only thing that stands out.
	if last := b.score[len(v)-1]; !math.IsNaN(last) && last <= 3 {
		t.Errorf("the spike should score high, got %v", last)
	}
}

// A spike must not corrupt the baseline for the minutes after it. That is the
// whole reason this is a median rather than a mean.
func TestASpikeDoesNotBecomeTheNewNormal(t *testing.T) {
	v := make([]float64, baselineWindow*2)
	for i := range v {
		v[i] = 10
	}
	for i := baselineWindow; i < baselineWindow+3; i++ {
		v[i] = 400 // a three-minute incident
	}
	b := trailingBaseline(v)

	// Ten minutes later, with the incident still inside the trailing window,
	// "normal" should still be about ten -- a mean would read nearer sixty.
	after := b.centre[baselineWindow+10]
	if after > 20 {
		t.Errorf("the baseline absorbed the spike: normal reads %v, want ~10", after)
	}
}

// A flat series has no scale, so there is no honest number of deviations to
// report. It must decline to answer rather than divide by zero or invent a clamp.
func TestAFlatBaselineDeclinesToScore(t *testing.T) {
	v := make([]float64, baselineWindow+2)
	// every minute identical, then one that is not
	v[len(v)-1] = 7
	b := trailingBaseline(v)
	if got := b.score[len(v)-1]; !math.IsNaN(got) {
		t.Errorf("a zero-spread baseline should not score, got %v", got)
	}
	// And a value equal to the flat baseline is exactly normal, which IS sayable.
	if got := b.score[baselineWindow]; got != 0 {
		t.Errorf("matching a flat baseline is 0 deviations, got %v", got)
	}
}

// Requests can be attributed to a container, but only because the app said so.
// komizo cannot work it out: the shared proxy only ever talks to the app's
// gate, and what happens after that is inside the app.
func TestRequestsAttributeToAContainerWhenTheAppSaysSo(t *testing.T) {
	out := strings.Join([]string{
		"metric\t600\tblog\tapi\t10\t0\t0\t2",
		"metric\t600\tblog\tdb\t4\t0\t0\t0",
		"metric\t600\tblog\t\t6\t0\t0\t0", // a hostname with no annotation
	}, "\n")
	rows := parseMetrics(out)
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}

	// The app is the sum over every container, including the unannotated one.
	// Total is every class, 5xx included: a failed request is still a request.
	whole := seriesFor(rows, "blog", 600, 600)
	if whole.total[0] != 22 {
		t.Errorf("app total = %v, want (10+2)+4+6", whole.total[0])
	}
	if whole.errors[0] != 2 {
		t.Errorf("app 5xx = %v, want 2", whole.errors[0])
	}

	// One container is only its own.
	api := seriesForService(rows, "blog", "api", 600, 600)
	if api.total[0] != 12 || api.errors[0] != 2 {
		t.Errorf("api = %v/%v, want 12/2", api.total[0], api.errors[0])
	}
	db := seriesForService(rows, "blog", "db", 600, 600)
	if db.total[0] != 4 {
		t.Errorf("db total = %v, want 4", db.total[0])
	}

	// "" is a real bucket -- this app declared a hostname and did not say what
	// serves it -- not a sentinel for "everything".
	un := seriesForService(rows, "blog", "", 600, 600)
	if un.total[0] != 6 {
		t.Errorf("unannotated = %v, want 6", un.total[0])
	}

	// A container no hostname names is unmeasurable, not idle. The view has to
	// be able to tell those apart.
	if !servesAnyHostname(rows, "blog", "api") {
		t.Error("api is named by a hostname")
	}
	if servesAnyHostname(rows, "blog", "worker") {
		t.Error("worker is named by no hostname and must not look measured")
	}
}

// l on the monitor opens the log of what is being watched -- the proxy's for
// the box, the app's for an app, the container's for a container -- and esc
// from a log opened there goes back to the monitor, not the list.
func TestTheMonitorOffersTheSubjectsLog(t *testing.T) {
	m := testModel()
	m.width, m.height = 100, 30
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running"},
	}

	// An app.
	m.cursor = rowOf(m, focusApp)
	mon, _ := sendCmd(m, "enter")
	logs, cmd := sendCmd(mon, "l")
	if logs.scr != screenLogs || cmd == nil {
		t.Fatalf("l on an app's monitor should fetch its log, got %v", logs.scr)
	}
	if logs.logsOf != "app:blog" || logs.logsApp != "blog" || logs.logsSvc != "" {
		t.Errorf("the log is %q/%q/%q, want the app's", logs.logsOf, logs.logsApp, logs.logsSvc)
	}
	if back := send(logs, "esc"); back.scr != screenMonitor {
		t.Errorf("esc should return to the monitor it came from, got %v", back.scr)
	}

	// A container.
	m.cursor = rowOf(m, focusContainer)
	mon, _ = sendCmd(m, "enter")
	if logs, _ = sendCmd(mon, "l"); logs.logsOf != "blog-web-1" || logs.logsSvc != "web" {
		t.Errorf("the log is %q/%q, want the container's", logs.logsOf, logs.logsSvc)
	}

	// The box: the proxy's log, which is the only box-wide one there is.
	m.cursor = rowOf(m, focusProxy)
	mon, _ = sendCmd(m, "enter")
	if logs, _ = sendCmd(mon, "l"); logs.logsOf != proxyContainer {
		t.Errorf("the box's log is %q, want the proxy's", logs.logsOf)
	}

	// A box with no proxy has no box-wide log: the key does nothing, and the
	// footer does not offer it.
	mon.proxy = proxyRow{}
	if none := send(mon, "l"); none.scr != screenMonitor {
		t.Errorf("l with no proxy should stay put, got %v", none.scr)
	}
	if strings.Contains(stripANSI(mon.monitorKeys()), "logs") {
		t.Error("the footer should not offer a log that cannot be shown")
	}

	// And a log opened from the index still returns to the index.
	m.cursor = rowOf(m, focusProxy)
	fromIndex, _ := sendCmd(m, "l")
	if back := send(fromIndex, "esc"); back.scr != screenIndex {
		t.Errorf("esc from an index log should return to the list, got %v", back.scr)
	}
}

// And the reverse: m on a log window jumps to the monitor of the same
// subject, so the two screens are one keypress apart in both directions.
func TestALogOffersItsSubjectsMonitor(t *testing.T) {
	m := testModel()
	m.width, m.height = 100, 30
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "web", name: "blog-web-1", state: "running"},
	}

	// A container's log, from the index.
	m.cursor = rowOf(m, focusContainer)
	logs, _ := sendCmd(m, "l")
	mon, cmd := sendCmd(logs, "m")
	if mon.scr != screenMonitor || cmd == nil {
		t.Fatalf("m on a container's log should open its monitor, got %v", mon.scr)
	}
	if mon.monitorOf != "blog" || mon.monitorSvc != "web" {
		t.Errorf("the monitor is for %q/%q, want blog/web", mon.monitorOf, mon.monitorSvc)
	}

	// An app's log carries no container, and neither should its monitor.
	m.cursor = rowOf(m, focusApp)
	logs, _ = sendCmd(m, "l")
	if mon, _ = sendCmd(logs, "m"); mon.monitorOf != "blog" || mon.monitorSvc != "" {
		t.Errorf("the monitor is for %q/%q, want blog and no container", mon.monitorOf, mon.monitorSvc)
	}

	// The proxy's log names no app, and its monitor is the whole box.
	m.cursor = rowOf(m, focusProxy)
	logs, _ = sendCmd(m, "l")
	if mon, _ = sendCmd(logs, "m"); mon.monitorOf != "" || mon.monitorSvc != "" {
		t.Errorf("the proxy's log should open the box's monitor, got %q/%q", mon.monitorOf, mon.monitorSvc)
	}
}

// Enter works on a container row too, and the breadcrumb says which container
// -- otherwise a container's chart and its app's are indistinguishable, and
// the difference is the whole reason to open one.
func TestTheMonitorOpensForAContainer(t *testing.T) {
	m := testModel()
	m.width, m.height = 110, 30
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "api", name: "blog-api-1", state: "running"},
	}
	m.cursor = rowOf(m, focusContainer)

	next, cmd := sendCmd(m, "enter")
	if next.scr != screenMonitor {
		t.Fatalf("enter on a container should open the monitor, got %v", next.scr)
	}
	if cmd == nil {
		t.Error("it should fetch")
	}
	if next.monitorOf != "blog" || next.monitorSvc != "api" {
		t.Errorf("the monitor is for %q/%q, want blog/api", next.monitorOf, next.monitorSvc)
	}
	if got := next.crumb(); !strings.Contains(got, "blog") || !strings.Contains(got, "api") {
		t.Errorf("crumb = %q, want it to name both app and container", got)
	}

	// The app's own chart names no container.
	a := testModel()
	a.cursor = rowOf(a, focusApp)
	app, _ := sendCmd(a, "enter")
	if app.monitorSvc != "" {
		t.Errorf("an app chart should carry no container, got %q", app.monitorSvc)
	}
	if strings.Contains(app.crumb(), "/ api /") {
		t.Errorf("crumb = %q, should not name a container", app.crumb())
	}
}

// The breadcrumb names every level: which app, which container inside it, and
// what you are looking at. A container's log and its app's log are different
// documents, and "astry logs" was true of both.
func TestCrumbsNameTheWholePath(t *testing.T) {
	m := testModel()
	m.width, m.height = 110, 30
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "api", name: "blog-api-1", state: "running"},
	}

	// A container's log.
	c := m
	c.cursor = rowOf(c, focusContainer)
	c, _ = sendCmd(c, "l")
	if got := c.crumb(); got != "blog / api / logs" {
		t.Errorf("container log crumb = %q, want \"blog / api / logs\"", got)
	}

	// The app's log is the stack's, and says so with one fewer level.
	a := m
	a.cursor = rowOf(a, focusApp)
	a, _ = sendCmd(a, "l")
	if got := a.crumb(); got != "blog / logs" {
		t.Errorf("app log crumb = %q, want \"blog / logs\"", got)
	}

	// The proxy belongs to no app. It names itself rather than being nested
	// under something it is not part of.
	p := netModel()
	p.width, p.height = 110, 30
	p.cursor = rowOf(p, focusProxy)
	p, _ = sendCmd(p, "l")
	if got := p.crumb(); got != "proxy / logs" {
		t.Errorf("proxy log crumb = %q, want \"proxy / logs\"", got)
	}

	// The monitor takes the same shape, so the two screens read alike.
	r := m
	r.cursor = rowOf(r, focusContainer)
	r, _ = sendCmd(r, "enter")
	if got := r.crumb(); got != "blog / api / monitor" {
		t.Errorf("container monitor crumb = %q", got)
	}
}

// Content above the first selectable row must stay reachable. reflow will not
// scroll above the cursor, and no keypress moves the cursor higher than its
// first item -- so without a rule for that case, the box's own facts scroll away
// once and never come back.
func TestTheTopOfTheIndexStaysReachable(t *testing.T) {
	m := testModel()
	m.width, m.height = 90, 14
	m.apps = nil
	for _, n := range []string{"alpha", "bravo", "charlie", "delta", "echo"} {
		m.apps = append(m.apps, appRow{name: n, running: "1", version: "abc", image: "ghcr.io/x/" + n,
			containers: []containerRow{{app: n, service: "api", name: n + "-api-1", state: "running"}}})
	}
	m.reflow()

	// Away from the top, then all the way back.
	for i := 0; i < 20; i++ {
		m = send(m, "down")
	}
	if m.scroll == 0 {
		t.Fatal("the fixture is too short to scroll; the test proves nothing")
	}
	for i := 0; i < 30; i++ {
		m = send(m, "up")
	}
	if m.scroll != 0 {
		t.Errorf("back at the first row, scroll = %d, want 0", m.scroll)
	}
	if v := stripANSI(m.View()); !strings.Contains(v, "alpine") {
		t.Errorf("the first row of the page should be visible again:\n%s", v)
	}
}

// The wheel moves the page and never the selection: scrolling to look at
// something is not choosing it. And the page must not snap back to the cursor
// while the wheel is driving, or it cannot be scrolled at all.
func TestTheWheelMovesThePageNotTheCursor(t *testing.T) {
	m := testModel()
	m.width, m.height = 90, 14
	m.apps = nil
	for _, n := range []string{"alpha", "bravo", "charlie", "delta", "echo"} {
		m.apps = append(m.apps, appRow{name: n, running: "1", version: "abc", image: "ghcr.io/x/" + n,
			containers: []containerRow{{app: n, service: "api", name: n + "-api-1", state: "running"}}})
	}
	m.reflow()
	cursor := m.cursor

	next, _ := m.Update(tea.MouseMsg{Type: tea.MouseWheelDown})
	m = next.(model)
	if m.cursor != cursor {
		t.Errorf("the wheel moved the selection: %d -> %d", cursor, m.cursor)
	}
	if m.scroll == 0 {
		t.Error("the wheel did not move the page")
	}

	// It keeps moving rather than being dragged back to the cursor.
	was := m.scroll
	next, _ = m.Update(tea.MouseMsg{Type: tea.MouseWheelDown})
	m = next.(model)
	if m.scroll <= was {
		t.Errorf("a second notch did not advance: %d -> %d", was, m.scroll)
	}

	// A key hands the page back to the cursor.
	m = send(m, "down")
	if m.freeScroll {
		t.Error("a keypress should return the page to the cursor")
	}
}

// Failures need their own baseline. A median has no scale on a series of zeros,
// so the robust version declines to score and the line never draws -- correct,
// and useless. Counts have a spread a median does not capture.
func TestFailuresScoreAgainstAPoissonBaseline(t *testing.T) {
	// A window that normally sees four failures a minute.
	v := make([]float64, baselineWindow+2)
	for i := range v {
		v[i] = 4
	}
	v[len(v)-1] = 16

	// The robust baseline cannot score this: every value identical means no
	// spread at all.
	if got := trailingBaseline(v).score[len(v)-1]; !math.IsNaN(got) {
		t.Errorf("a flat median baseline should decline, got %v", got)
	}
	// Poisson can: variance equals the mean, so the unit is sqrt(4) = 2, and
	// sixteen against a mean of four is six of them.
	p := trailingPoisson(v)
	if got := p.score[len(v)-1]; math.Abs(got-6) > 0.001 {
		t.Errorf("poisson score = %v, want (16-4)/sqrt(4) = 6", got)
	}

	// Quiet stays quiet: zero failures against a baseline of zero is exactly
	// normal, and must not read as an event.
	z := make([]float64, baselineWindow+2)
	if got := trailingPoisson(z).score[len(z)-1]; got != 0 {
		t.Errorf("no failures against no failures = %v, want 0", got)
	}

	// And the first failure after a clean window is off the scale, not at some
	// point on it -- there is no spread to measure it against.
	z[len(z)-1] = 1
	if got := trailingPoisson(z).score[len(z)-1]; got != devLimit {
		t.Errorf("first failure after a clean window = %v, want the ceiling (%d)", got, devLimit)
	}
}

// The box's chart is every app added together -- and NOT every request. Traffic
// matching no app is counted for nobody, which is the honest limit of a number
// built by attribution.
func TestTheBoxChartSumsEveryApp(t *testing.T) {
	rows := []metricRow{
		{minute: 600, app: "blog", service: "api", c2: 10, c5: 1},
		{minute: 600, app: "shop", c2: 5},
		{minute: 660, app: "blog", c2: 2},
	}
	s := seriesForBox(rows, 600, 660)
	if s.total[0] != 16 {
		t.Errorf("minute one = %v, want (10+1)+5", s.total[0])
	}
	if s.errors[0] != 1 {
		t.Errorf("minute one 5xx = %v, want 1", s.errors[0])
	}
	if s.total[1] != 2 {
		t.Errorf("minute two = %v, want 2", s.total[1])
	}
	// One app's own view is unchanged by the box's existing.
	if b := seriesFor(rows, "blog", 600, 660); b.total[0] != 11 {
		t.Errorf("blog alone = %v, want 11", b.total[0])
	}
}

// A container can hold the same alias twice. The proxy does: its compose
// service name and its container_name are both "komizo-proxy", and docker
// records each as an alias on the shared network.
//
// Counting mentions rather than containers reported that as a clash with
// itself -- "komizo-proxy resolves to 2 containers (komizo-proxy,
// komizo-proxy)" -- on a box with exactly one proxy. A warning that traffic is
// splitting at random, about traffic that cannot split.
func TestOneContainerHoldingAnAliasTwiceIsNotAClash(t *testing.T) {
	n := netRow{name: "edge", members: []netMember{
		{container: "komizo-proxy", aliases: []string{"komizo-proxy", "komizo-proxy"}},
		{container: "ormos-ormos-gate-1", aliases: []string{"ormos-gate", "ormos-ormos-gate-1"}},
	}}
	if d := n.duplicateAliases(); len(d) != 0 {
		t.Errorf("reported a clash on a box with one proxy: %v", d)
	}

	// And the real fault still is one: two DIFFERENT containers claiming a
	// name, which does split traffic and did take an app down once.
	n.members = append(n.members, netMember{
		container: "astry-astry-gate-1",
		aliases:   []string{"komizo-proxy", "astry-gate"},
	})
	d := n.duplicateAliases()
	if len(d["komizo-proxy"]) != 2 {
		t.Errorf("two containers claiming one name should clash, got %v", d)
	}
}

// stubClipboard replaces the system clipboard for one test, and puts it back.
//
// What is under test is the MARK -- which value the interface claims is on the
// clipboard -- and that is komizo's own logic. Whether wl-copy is installed is
// the machine's business and has no place deciding whether this passes.
func stubClipboard(t *testing.T) {
	t.Helper()
	real := copyToClipboard
	copyToClipboard = func(string) error { return nil }
	t.Cleanup(func() { copyToClipboard = real })
}

// --- on-demand TLS gate ----------------------------------------------------

func TestGateIsParsedFromInventory(t *testing.T) {
	_, _, proxy, _, _ := parseInventory(
		"proxy\trunning\tedge\tcaddy:2\tUp 3 hours\t\t\t\n" +
			"gate\thttp://ormos-gate/internal/tls-ask\n")
	if proxy.tlsAsk != "http://ormos-gate/internal/tls-ask" {
		t.Errorf("the gate line should set proxy.tlsAsk, got %q", proxy.tlsAsk)
	}
}

func TestNoGateLineMeansNoGate(t *testing.T) {
	_, _, proxy, _, _ := parseInventory("proxy\trunning\tedge\tcaddy:2\tUp 3 hours\t\t\t\n")
	if proxy.tlsAsk != "" {
		t.Errorf("absent gate line should leave tlsAsk empty, got %q", proxy.tlsAsk)
	}
}

func TestAWildcardWithoutAGateWarnsOnTheGateRow(t *testing.T) {
	m := testModel()
	m.apps[0].routes = []routeRow{{app: "blog", sites: "*.iframe.example.com", upstream: "blog-gate"}}
	m.proxy.tlsAsk = ""
	if !m.anyWildcard() {
		t.Fatal("a *. route should count as a wildcard")
	}
	g, text := m.gateLine()
	if g != dot("warn") {
		t.Errorf("the gate row should warn (amber) when a wildcard has no gate")
	}
	// No "off" word -- the amber dot is the state; the text names the app that
	// needs it and what to press.
	if !strings.Contains(text, "blog") {
		t.Errorf("the gate row should name the app that needs it: %q", text)
	}
}

func TestAConfiguredGateShowsOnTheGateRow(t *testing.T) {
	m := testModel()
	m.proxy.tlsAsk = "http://blog-gate/internal/tls-ask"
	g, text := m.gateLine()
	if g != dot("ok") {
		t.Errorf("a configured gate should show a green dot")
	}
	// No "on" word -- the green dot is the state; the value is the endpoint itself.
	if !strings.Contains(text, "blog-gate/internal/tls-ask") {
		t.Errorf("the gate row should show the ask URL: %q", text)
	}
}

func TestNoWildcardOffGateIsNotShouted(t *testing.T) {
	m := testModel() // blog has only a concrete hostname
	m.proxy.tlsAsk = ""
	if m.anyWildcard() {
		t.Fatal("no app declares a wildcard here")
	}
	// Off is fine when nothing needs it: a neutral dot, not a warning.
	if g, _ := m.gateLine(); g == dot("warn") {
		t.Errorf("a box with no wildcard app should not warn about a missing gate")
	}
}

func TestTheGateRowIsPresentWhenTheProxyIs(t *testing.T) {
	m := testModel()
	if rowOf(m, focusGate) < 0 {
		t.Fatal("a gate row should be reachable when the proxy is installed")
	}
	m.proxy = proxyRow{} // no proxy
	if rowOf(m, focusGate) >= 0 {
		t.Error("there should be no gate row without a proxy")
	}
}

func TestTheGateRowRendersInTheIndex(t *testing.T) {
	m := testModel()
	m.proxy.tlsAsk = "http://blog-gate/internal/tls-ask"
	v := stripANSI(m.View())
	if !strings.Contains(v, "tls gate") {
		t.Errorf("the index should show a tls gate row:\n%s", v)
	}
}

func TestEnterOnTheGateRowEditsTheGate(t *testing.T) {
	m := testModel()
	m.proxy.tlsAsk = "http://old/ask"
	m.cursor = rowOf(m, focusGate)
	m = send(m, "enter")
	if m.prompt == nil || m.prompt.kind != promptInput {
		t.Fatalf("enter on the gate row should open a URL input, got %+v", m.prompt)
	}
	if m.prompt.typed != "http://old/ask" {
		t.Errorf("the input should prefill the current gate for editing, got %q", m.prompt.typed)
	}
	m.prompt.typed = "ftp://nope"
	if m.prompt.answered() {
		t.Error("a non-http(s) ask URL should be rejected")
	}
	m.prompt.typed = "http://ormos-gate/internal/tls-ask"
	if !m.prompt.answered() {
		t.Error("a valid ask URL should be accepted")
	}
	m.prompt.typed = ""
	if !m.prompt.answered() {
		t.Error("an empty value should be accepted -- it clears the gate")
	}
}

func TestTheCliAndServerVersionsAreTwoRows(t *testing.T) {
	m := testModel()
	m.scr, m.width, m.height = screenIndex, 96, 30
	// Up to date: same content stamp and same version as this komizo.
	m.srv.komizoInstalled = true
	m.srv.komizo = komizoStamp()
	m.srv.komizoVersion = "0.0.1" // distinct from the cli's "dev", to tell them apart

	// The cli row shows the running version; the server row shows the box's.
	if got := stripANSI(m.komizoCliLine()); !strings.Contains(got, versionLabel(versionText())) {
		t.Errorf("the cli row should show the running version, got %q", got)
	}
	if got := stripANSI(m.komizoServerLine()); !strings.Contains(got, versionLabel("0.0.1")) {
		t.Errorf("the server row should show the box version, got %q", got)
	}

	// Two labelled rows on the page, server directly above cli: the box's version
	// reads first, yours sits under it for the comparison.
	body := stripANSI(m.pageBody())
	si := strings.Index(body, "komizo server")
	ci := strings.Index(body, "komizo cli")
	if ci < 0 || si < 0 {
		t.Fatalf("both komizo rows should be labelled on the page:\n%s", body)
	}
	if si > ci {
		t.Errorf("the server row should sit above the cli row:\n%s", body)
	}
}
