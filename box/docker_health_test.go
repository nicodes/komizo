package box

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"text/template"
)

func TestUncheckedContainerDoesNotDiscardBatchInspection(t *testing.T) {
	objects := map[string]map[string]any{}
	for i, id := range []string{"api", "proxy"} {
		state := map[string]any{
			"StartedAt": "2026-10-10T12:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z",
			"ExitCode": 0, "Pid": 101 + i,
		}
		if id == "api" {
			state["Health"] = map[string]any{"Status": "healthy"}
		}
		objects[id] = map[string]any{
			"Id": id, "State": state,
			"NetworkSettings": map[string]any{"Networks": map[string]any{
				"shared": map[string]any{"Aliases": []string{id}},
			}},
			"Mounts": []map[string]any{{"Type": "volume", "Name": id + "-data", "Source": "/volumes/" + id}},
		}
	}
	calls := 0
	p := &Probe{Docker: func(_ context.Context, args ...string) (string, error) {
		calls++
		switch args[0] {
		case "ps":
			return "api\tapi-1\trunning\tUp\tapi\timage\t/srv/app\nproxy\tproxy-1\trunning\tUp\tproxy\timage\t/srv/proxy\n", nil
		case "inspect":
			// Docker rejects missing map keys. Execute the actual production
			// template, including a container without a Health object.
			tmpl, err := template.New("inspect").Option("missingkey=error").Parse(args[2])
			if err != nil {
				return "", err
			}
			var b bytes.Buffer
			for _, id := range args[3:] {
				if err := tmpl.Execute(&b, objects[id]); err != nil {
					return "", err
				}
				b.WriteByte('\n')
			}
			return b.String(), nil
		default:
			return "", fmt.Errorf("unexpected Docker command: %s", strings.Join(args, " "))
		}
	}}
	inv := p.dockerInventory(context.Background())
	if calls != 2 || len(inv.byID) != 2 {
		t.Fatalf("expected one shared inspection: calls=%d containers=%d", calls, len(inv.byID))
	}
	for id, c := range inv.byID {
		if c.pid == 0 || c.startedAt.IsZero() || len(c.networks["shared"]) != 1 || len(c.mounts) != 1 {
			t.Fatalf("%s lost batch metadata: %+v", id, c)
		}
	}
	if inv.byID["api"].health != "healthy" || inv.byID["proxy"].health != "" {
		t.Fatalf("health missing or invented: api=%q proxy=%q", inv.byID["api"].health, inv.byID["proxy"].health)
	}
}
