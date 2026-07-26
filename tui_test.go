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
		{name: "blog", user: "cd-blog", dir: "/srv/blog", version: "a1b2c3d4e5f6a7b8", running: "3", image: "ghcr.io/you/blog-config"},
		{name: "shop", user: "cd-shop", dir: "/srv/shop", version: "none", running: "0", image: "ghcr.io/you/shop-config"},
	}
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
	for _, want := range []string{"blog", "cd-blog", "ghcr.io/you/blog-config", "shop"} {
		if !strings.Contains(v, want) {
			t.Errorf("list view is missing %q", want)
		}
	}
	// The directory is deliberately not in the list -- it is derivable from the
	// app name and would cost a column. It belongs on the detail screen.
	if strings.Contains(v, "/srv/blog") {
		t.Error("the list should stay compact; the directory belongs in the detail view")
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
	for _, want := range []string{"shop", "/srv/shop", "cd-shop", "deploy-shop", "set-secret-shop"} {
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
		"app\tblog\tcd-blog\t/srv/blog\ta1b2\t2\tghcr.io/you/blog-config",
		"app\tshop\tcd-shop\t/srv/shop\tnone\t0\tghcr.io/you/shop-config",
		"orphan\tghost",
		"", // trailing blank, as the server emits
	}, "\n")
	apps, orphans := parseInventory(out)
	if len(apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(apps))
	}
	if apps[0].name != "blog" || apps[0].image != "ghcr.io/you/blog-config" {
		t.Errorf("first app parsed wrong: %+v", apps[0])
	}
	if len(orphans) != 1 || orphans[0] != "ghost" {
		t.Errorf("expected one orphan named ghost, got %v", orphans)
	}
}
