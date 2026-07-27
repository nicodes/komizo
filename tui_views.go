package main

import (
	"fmt"
	"strings"
)

func viewList(m model) string {
	var b strings.Builder

	if len(m.apps) == 0 {
		b.WriteString("\n" + gutter + titleStyle.Render("No apps yet") + "\n")
		b.WriteString("\n" + para(gutter, "An app is a compose stack with its own directory, deploy account\nand privileged commands."))
		b.WriteString("\n" + gutter + keyStyle.Render("a") + dimStyle.Render(" adds one.") + "\n")
		b.WriteString(m.footer())
		b.WriteString(help("a", "add an app", "s", "server", "R", "refresh", "q", "quit"))
		return b.String()
	}

	rows := [][]string{{"APP", "ACCOUNT", "VERSION", "UP", "ROUTES"}}
	for _, a := range m.apps {
		rows = append(rows, []string{
			a.name,
			dimStyle.Render(a.user),
			short(a.version),
			upCount(a.running),
			routesOrNone(a.routes),
		})
	}
	b.WriteString("\n" + table(rows, m.cursor))

	if m.status != "" {
		b.WriteString("\n" + gutter + warnStyle.Render(m.status) + "\n")
	}
	b.WriteString(m.footer())
	b.WriteString(help(
		"↑↓", "select", "enter", "details", "a", "add", "s", "server",
		"r", "rotate key", "x", "remove", "R", "refresh", "q", "quit"))
	return b.String()
}

// footer is the standing state of the box under the app list: whether the thing
// every app depends on is working. Always present, so its absence never has to
// be interpreted.
func (m model) footer() string {
	var b strings.Builder
	b.WriteString("\n" + gutter + listProxyLine(m.proxy) + "\n")
	if d := m.net.duplicateAliases(); len(d) > 0 {
		b.WriteString(gutter + dot("err") + " " + errStyle.Render(fmt.Sprintf(
			"%d alias clash on %s", len(d), m.net.name)) +
			dimStyle.Render(" — press s") + "\n")
	}
	return b.String()
}

func viewDetail(m model) string {
	a := m.apps[m.cursor]
	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render(a.name) + "\n")

	b.WriteString(section("where"))
	b.WriteString(kv("account", dimStyle.Render(a.user)))
	b.WriteString(kv("directory", dimStyle.Render(a.dir)))
	b.WriteString(kv("config image", a.image))

	b.WriteString(section("now"))
	b.WriteString(kv("version", short(a.version)))
	b.WriteString(kv("containers", upCount(a.running)))
	b.WriteString(kv("routes", routesOrNone(a.routes)))

	b.WriteString(section("what CI may run"))
	b.WriteString(kv("deploy", dimStyle.Render("doas /usr/local/bin/deploy-"+a.name)))
	b.WriteString(kv("secrets", dimStyle.Render("doas /usr/local/bin/set-secret-"+a.name)))

	b.WriteString("\n" + para(gutter, "That is the whole grant. This account can deploy a tag that already\nexists in your registry, and set secrets it cannot read back."))
	b.WriteString(help("c", "config image", "r", "rotate key", "x", "remove", "esc", "back"))
	return b.String()
}

// short trims a commit SHA to something readable without losing which it is.
func short(v string) string {
	if v == "" || v == "none" {
		return dimStyle.Render("never deployed")
	}
	if len(v) > 12 {
		return v[:12]
	}
	return v
}

// upCount colours the container count, because zero is the number that matters
// and it is otherwise indistinguishable from any other digit at a glance.
func upCount(n string) string {
	if n == "0" || n == "" {
		return errStyle.Render("0")
	}
	return okStyle.Render(n)
}

// listProxyLine is the one-line summary under the app list. Always shown,
// including when there is no proxy: "apps publish their own ports" is
// information, not an absence of it.
func listProxyLine(p proxyRow) string {
	switch {
	case !p.installed:
		return dot("") + dimStyle.Render(" no shared proxy — apps publish their own ports · press s")
	case !p.running():
		return dot("err") + " " + errStyle.Render("proxy is NOT running") +
			dimStyle.Render(" — nothing is being served · press s")
	default:
		return dot("ok") + dimStyle.Render(" proxy running on "+p.network)
	}
}

// routesOrNone keeps the column readable when an app publishes nothing through
// the proxy, which is normal for a worker or a cron job.
func routesOrNone(routes string) string {
	if routes == "" {
		return dimStyle.Render("—")
	}
	return routes
}
