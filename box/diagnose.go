package box

import (
	"fmt"
	"sort"
	"strings"
)

// Diagnose is what is wrong with a box, worked out from one reading of it.
//
// This is most of the product. Every condition below is invisible from outside
// the machine -- the box is up, the proxy answers, the certificate is valid,
// and one hostname 502s. Shipping the diagnosis rather than the raw facts is
// the difference between a page of numbers and something worth being woken by.
//
// A pure function of a Report, deliberately. It is therefore testable without a
// machine, it can be re-run over a stored report to see what would have fired,
// and there is exactly one definition of "broken" for the CLI, the monitor, and
// whatever alerts later.
//
// Ordered most severe first, so a reader that shows one shows the worst.
func Diagnose(r Report) []Problem {
	var out []Problem

	// A stopped proxy is first because it takes down every hostname on the box
	// at once, whatever the apps behind it are doing.
	if r.Proxy != nil && !r.Proxy.Running() {
		out = append(out, Problem{
			Kind:   ProblemProxyStopped,
			Detail: "the shared reverse proxy is not running -- nothing is being served",
		})
	}

	// Two DIFFERENT containers claiming one name on the shared network. Caddy
	// round-robins between them, so it fails intermittently rather than
	// outright, which is why it is worth surfacing rather than leaving to be
	// discovered.
	if r.Network != nil {
		dupes := duplicateAliases(*r.Network)
		for _, alias := range sortedKeys(dupes) {
			cs := dupes[alias]
			out = append(out, Problem{
				Kind: ProblemAliasClash,
				Detail: fmt.Sprintf("%q resolves to %d containers on network %q (%s) -- traffic to it is split between them at random",
					alias, len(cs), r.Network.Name, strings.Join(cs, ", ")),
			})
		}
	}

	attached := map[string]bool{}
	if r.Network != nil {
		for _, m := range r.Network.Members {
			attached[m.Container] = true
		}
	}

	for _, a := range r.Apps {
		// An app publishing hostnames with nothing of its own on the shared
		// network. The proxy has routes pointing at an alias that resolves to
		// nothing, so every one of those names 502s while the containers
		// themselves look perfectly healthy.
		//
		// Only when something is actually running: an app that is entirely down
		// is a different problem, reported below, and saying both would be two
		// alerts for one fault.
		if len(a.Hosts) > 0 && a.Running() > 0 && r.Network != nil {
			any := false
			for _, c := range a.Containers {
				if c.State == "running" && attached[c.Name] {
					any = true
					break
				}
			}
			if !any {
				out = append(out, Problem{
					Kind: ProblemDetached,
					App:  a.Name,
					Detail: fmt.Sprintf("%s publishes %d hostname(s) but no running container is attached to network %q",
						a.Name, len(a.Hosts), r.Network.Name),
				})
			}
		}

		// RUNNING, UNDER A RECORD THAT SAYS STOPPED. komizo#57.
		//
		// Nothing on this box compares the marker against the containers that
		// are actually up, so a record disagreeing with reality stays that way
		// silently -- and it is the direction that switches paging OFF. app_down
		// below keys on `!a.Stopped`, so an app in this state never pages, for
		// as long as the disagreement lasts, with nothing on the report saying
		// alerting is off for it. The only thing that clears the marker is
		// somebody running `komizo start` on an app they can plainly see is
		// already up, which is not a thing anybody does.
		//
		// REPORTED, NOT RECONCILED, and that is the harder half deliberately
		// left alone. Clearing the marker here would mean a container that
		// restarts on its own -- a `restart: always` policy, a box rebooting --
		// silently overrules a person who asked for the app to be down. Saying
		// so makes the class of bug visible; deciding who wins is a separate
		// question with a worse failure mode if it is got wrong.
		//
		// WHAT STILL CREATES THIS. komizo#54 removed the CI deploy that started
		// a stopped app, #62 removed the stop that lands mid-deploy, and #66
		// removed the per-service start. What remains is a box that ran an older
		// script before upgrading, and anybody typing `docker compose up` by
		// hand -- which is not a thing to design out.
		if a.Stopped && a.Running() > 0 {
			out = append(out, Problem{
				Kind: ProblemStoppedButRunning,
				App:  a.Name,
				Detail: fmt.Sprintf("%s is recorded as stopped but %d of its %d container(s) are running, "+
					"so it cannot report as down: start it to clear the record, or stop it again",
					a.Name, a.Running(), len(a.Containers)),
			})
		}

		// Down, and not on purpose.
		//
		// Stopped is a decision and must never page anyone -- which is the whole
		// reason the box records it. Nothing outside the machine can tell a
		// deliberate stop from a crash, so the distinction has to be made here.
		if !a.Stopped && len(a.Containers) > 0 && a.Running() == 0 {
			out = append(out, Problem{
				Kind:   ProblemAppDown,
				App:    a.Name,
				Detail: fmt.Sprintf("%s has %d container(s) and none of them are running", a.Name, len(a.Containers)),
			})
		}
	}

	// A wildcard hostname can only get a certificate through on-demand TLS,
	// which needs the proxy's ask gate. Reported before the deploy that fails
	// for it rather than after.
	if r.Proxy != nil && r.Proxy.TLSAsk == "" {
		var wild []string
		for _, a := range r.Apps {
			for _, h := range a.Hosts {
				if strings.HasPrefix(strings.TrimSpace(h.Name), "*.") {
					wild = append(wild, a.Name)
					break
				}
			}
		}
		if len(wild) > 0 {
			out = append(out, Problem{
				Kind: ProblemNoTLSGate,
				Detail: fmt.Sprintf("%s use a wildcard hostname but no on-demand TLS gate is set -- their certificates will fail",
					strings.Join(wild, ", ")),
			})
		}
	}

	for _, o := range r.Orphans {
		out = append(out, Problem{
			Kind:   ProblemOrphanDir,
			App:    o,
			Detail: fmt.Sprintf("/srv/%s has no state file behind it -- left over from a removal?", o),
		})
	}
	return out
}

// duplicateAliases finds names that resolve to more than one container.
//
// Compose gives every service an alias equal to its service name, so two apps
// that both call a service "web" both answer to "web" here.
//
// Distinct CONTAINERS, not distinct mentions. A container can hold the same
// alias twice -- the proxy does, because its compose service name and its
// container_name are both "komizo-proxy" and docker records each as an alias --
// and counting mentions reports that as a clash with itself, warning about
// traffic splitting at random that could not happen.
func duplicateAliases(n Network) map[string][]string {
	seen := map[string][]string{}
	for _, m := range n.Members {
		claimed := map[string]bool{}
		for _, a := range m.Aliases {
			if a == "" || claimed[a] {
				continue
			}
			claimed[a] = true
			seen[a] = append(seen[a], m.Container)
		}
	}
	dupes := map[string][]string{}
	for a, cs := range seen {
		if len(cs) > 1 {
			sort.Strings(cs)
			dupes[a] = cs
		}
	}
	return dupes
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
