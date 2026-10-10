package box

import "testing"

func TestRuntimeRequiresAllDeclaredServicesAndHealth(t *testing.T) {
	f := newFakeBox(t)
	app := App{Name: "example", Dir: "/srv/example"}
	if got := f.probe().runtimeState(app); got != "unknown" {
		t.Fatalf("missing desired state: %s", got)
	}
	f.write("/srv/example/compose.yml", `{"services":{"gate":{"restart":"unless-stopped"},"api":{"restart":"unless-stopped","healthcheck":{"test":["CMD","health"]}},"init":{"restart":"no"},"backup":{"profiles":["backup"]}}}`)
	app.Containers = []Container{{Service: "gate", State: "running"}, {Service: "api", State: "running", Health: "unhealthy"}, {Service: "init", State: "exited"}}
	if got := f.probe().runtimeState(app); got != "degraded" {
		t.Fatalf("unhealthy API: %s", got)
	}
	app.Containers[1].Health = "healthy"
	if got := f.probe().runtimeState(app); got != "running" {
		t.Fatalf("healthy workload with init: %s", got)
	}
	app.Containers = app.Containers[:1]
	if got := f.probe().runtimeState(app); got != "degraded" {
		t.Fatalf("missing API: %s", got)
	}
	app.Stopped = true
	if got := f.probe().runtimeState(app); got != "stopped" {
		t.Fatalf("deliberate stop: %s", got)
	}
}
