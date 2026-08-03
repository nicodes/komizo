package box

import (
	"strings"
	"testing"
)

// Diagnose is a pure function of a Report, so these need no machine at all --
// which is the point of computing the diagnosis from a document rather than
// during the probe.

func kinds(ps []Problem) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Kind)
	}
	return out
}

func has(ps []Problem, kind string) bool {
	for _, p := range ps {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

func TestAliasClashNeedsTwoDifferentContainers(t *testing.T) {
	// The real fault: two apps that both call a service "web". Caddy
	// round-robins between them, so it fails intermittently.
	r := Report{Network: &Network{Name: "edge", Members: []NetworkMember{
		{Container: "blog-web-1", Aliases: []string{"web", "blog-web"}},
		{Container: "shop-web-1", Aliases: []string{"web", "shop-web"}},
	}}}
	ps := Diagnose(r)
	if !has(ps, ProblemAliasClash) {
		t.Fatalf("want an alias clash, got %v", kinds(ps))
	}
	for _, p := range ps {
		if p.Kind == ProblemAliasClash && !strings.Contains(p.Detail, `"web"`) {
			t.Errorf("detail should name the alias: %q", p.Detail)
		}
	}
}

func TestOneContainerCannotClashWithItself(t *testing.T) {
	// The proxy holds "komizo-proxy" twice: its compose service name and its
	// container_name are both that, and docker records each as an alias.
	// Counting mentions reported it as clashing with itself.
	r := Report{Network: &Network{Name: "edge", Members: []NetworkMember{
		{Container: "komizo-proxy", Aliases: []string{"komizo-proxy", "komizo-proxy", "proxy"}},
	}}}
	if ps := Diagnose(r); has(ps, ProblemAliasClash) {
		t.Errorf("one container cannot clash with itself: %v", ps)
	}
}

func TestStoppedAppIsNotAnIncident(t *testing.T) {
	down := App{Name: "blog", Containers: []Container{{Service: "web", State: "exited"}}}
	if ps := Diagnose(Report{Apps: []App{down}}); !has(ps, ProblemAppDown) {
		t.Errorf("an app that is down should be reported, got %v", kinds(ps))
	}

	// The same app, stopped on purpose. Nothing outside the box can tell these
	// apart, which is the whole reason the box records the difference.
	down.Stopped = true
	if ps := Diagnose(Report{Apps: []App{down}}); has(ps, ProblemAppDown) {
		t.Errorf("a deliberate stop must not page anyone, got %v", kinds(ps))
	}
}

func TestDetachedAppPublishingRoutes(t *testing.T) {
	// Running containers, published hostnames, and nothing on the shared
	// network. Every one of those names 502s while the containers look healthy.
	r := Report{
		Network: &Network{Name: "edge", Members: []NetworkMember{{Container: "other-web-1"}}},
		Apps: []App{{
			Name:       "blog",
			Hosts:      []Host{{Name: "blog.example.com"}},
			Containers: []Container{{Service: "web", Name: "blog-web-1", State: "running"}},
		}},
	}
	if ps := Diagnose(r); !has(ps, ProblemDetached) {
		t.Fatalf("want detached, got %v", kinds(ps))
	}

	// Attached: no problem.
	r.Network.Members = append(r.Network.Members, NetworkMember{Container: "blog-web-1"})
	if ps := Diagnose(r); has(ps, ProblemDetached) {
		t.Errorf("an attached app is fine, got %v", kinds(ps))
	}
}

func TestDetachedIsNotReportedForAnAppThatIsSimplyDown(t *testing.T) {
	// Two alerts for one fault. An app with nothing running is not detached, it
	// is down, and that is what should be said.
	r := Report{
		Network: &Network{Name: "edge"},
		Apps: []App{{
			Name:       "blog",
			Hosts:      []Host{{Name: "blog.example.com"}},
			Containers: []Container{{Service: "web", Name: "blog-web-1", State: "exited"}},
		}},
	}
	ps := Diagnose(r)
	if has(ps, ProblemDetached) {
		t.Errorf("a down app should not also report as detached: %v", kinds(ps))
	}
	if !has(ps, ProblemAppDown) {
		t.Errorf("it should report as down: %v", kinds(ps))
	}
}

func TestWildcardWithoutAGateIsReportedBeforeTheDeployFails(t *testing.T) {
	r := Report{
		Proxy: &Proxy{State: "running"},
		Apps:  []App{{Name: "blog", Hosts: []Host{{Name: "*.blog.example.com"}}}},
	}
	if ps := Diagnose(r); !has(ps, ProblemNoTLSGate) {
		t.Fatalf("want a TLS gate warning, got %v", kinds(ps))
	}
	r.Proxy.TLSAsk = "https://gate/check"
	if ps := Diagnose(r); has(ps, ProblemNoTLSGate) {
		t.Errorf("a configured gate is not a problem: %v", kinds(ps))
	}
}

func TestStoppedProxyIsFirst(t *testing.T) {
	// It takes down every hostname on the box at once, whatever the apps behind
	// it are doing, so a reader that shows one problem should show this one.
	r := Report{
		Proxy:   &Proxy{State: "exited"},
		Orphans: []string{"leftover"},
		Apps:    []App{{Name: "blog", Containers: []Container{{State: "exited"}}}},
	}
	ps := Diagnose(r)
	if len(ps) == 0 || ps[0].Kind != ProblemProxyStopped {
		t.Errorf("proxy_stopped should sort first, got %v", kinds(ps))
	}
}

func TestAHealthyBoxHasNoProblems(t *testing.T) {
	r := Report{
		Proxy:   &Proxy{State: "running", TLSAsk: "https://gate/check"},
		Network: &Network{Name: "edge", Members: []NetworkMember{{Container: "blog-web-1", Aliases: []string{"blog-web"}}}},
		Apps: []App{{
			Name:       "blog",
			Hosts:      []Host{{Name: "blog.example.com"}},
			Containers: []Container{{Service: "web", Name: "blog-web-1", State: "running"}},
		}},
	}
	if ps := Diagnose(r); len(ps) != 0 {
		t.Errorf("healthy box reported %v", ps)
	}
}
