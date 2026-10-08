package box

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedPreviewNamesAreCollisionFreeAndPersisted(t *testing.T) {
	cfg := previewTestConfig(t)
	cfg.Knob, _ = ParsePreviewKnob("DOMAIN.prizm=preview.prizm.avior.studio\nSHARED_DOMAIN=preview.avior.studio\n")
	f := &fakeDocker{}
	for _, app := range []string{"prizm", "castledrop"} {
		rec, err := PreviewUp(context.Background(), f.run, cfg, app, 72, []string{"ghcr.io/test/" + app + "-gate:head"}, previewNow)
		if err != nil {
			t.Fatal(err)
		}
		want := app + "-pr72.preview.avior.studio"
		if rec.Host != want || rec.APIHost != "" {
			t.Fatalf("wrong endpoints: %+v", rec)
		}
		route, err := os.ReadFile(filepath.Join(cfg.RoutesDir, rec.RouteFile))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(route), want+" {") || strings.Contains(string(route), "-api.") {
			t.Fatalf("wrong static route: %s", route)
		}
		compose, _ := os.ReadFile(filepath.Join(previewDir(cfg.Root, rec.Project), "compose.yml"))
		if !strings.Contains(string(compose), "BASE_URL: https://"+want) {
			t.Fatalf("wrong origin: %s", compose)
		}
		stored, err := readPreviewRecord(previewDir(cfg.Root, rec.Project))
		if err != nil {
			t.Fatal(err)
		}
		changed, _ := ParsePreviewKnob("SHARED_DOMAIN=other.example\n")
		if stored.Host != want || stored.WebHost(changed) != want {
			t.Fatal("record lost its deployed hostname")
		}
	}
	records, err := ListPreviews(cfg.Root)
	if err != nil || len(records) != 2 {
		t.Fatalf("%+v: %v", records, err)
	}
	if records[0].GatePort == records[1].GatePort {
		t.Fatal("previews share a port")
	}
}

func TestSharedPreviewAPIAndLegacyCoexist(t *testing.T) {
	knob, _ := ParsePreviewKnob("DOMAIN=preview.gdam.dev\nDOMAIN.prizm=preview.prizm.avior.studio\nSHARED_DOMAIN.prizm=preview.avior.studio\n")
	shared, err := ResolvePreview(knob, "prizm", 72, true)
	if err != nil {
		t.Fatal(err)
	}
	if shared.Host != "prizm-pr72.preview.avior.studio" || shared.APIHost != "prizm-pr72-api.preview.avior.studio" {
		t.Fatalf("%+v", shared)
	}
	legacy, err := ResolvePreview(knob, "gdam", 72, true)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Host != "pr-72.preview.gdam.dev" || legacy.APIHost != "pr-72-api.preview.gdam.dev" {
		t.Fatalf("%+v", legacy)
	}
	r := PreviewRecord{App: "prizm", PR: 72, Project: "prizm-pr-72", Host: shared.Host, APIHost: shared.APIHost, Images: []string{"gate:head", "api:head"}}
	if route := previewRoute(r, knob); !strings.Contains(route, shared.Host+", "+shared.APIHost+" {") {
		t.Fatal(route)
	}
	if !knob.SharedAskAllow(shared.Host) || !knob.SharedAskAllow(shared.APIHost) {
		t.Fatal("shared endpoints refused")
	}
	for _, host := range []string{"other-pr72.preview.avior.studio", "prizm-pr0.preview.avior.studio", "prizm-pr72.extra.preview.avior.studio", "prizm-pr72.preview.avior.studio.evil.example"} {
		if knob.SharedAskAllow(host) {
			t.Errorf("allowed %s", host)
		}
	}
}

func TestInvalidSharedDomainFailsBeforeMutation(t *testing.T) {
	for _, domain := range []string{"*.preview.example", "preview.example/path", "preview..example", "-preview.example", "preview.example\nforged", strings.Repeat("x", 64) + ".example"} {
		t.Run(domain, func(t *testing.T) {
			cfg := previewTestConfig(t)
			cfg.Knob.SharedDomain = domain
			f := &fakeDocker{}
			if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 72, []string{"gate:head"}, previewNow); err == nil {
				t.Fatal("invalid shared domain accepted")
			}
			if len(f.calls) != 0 {
				t.Fatal("Docker called before host validation")
			}
			if records, _ := ListPreviews(cfg.Root); len(records) != 0 {
				t.Fatal("invalid request wrote state")
			}
		})
	}
}

func TestExistingPreviewRouteSurvivesSharedDomainOptIn(t *testing.T) {
	cfg := previewTestConfig(t)
	f := &fakeDocker{}
	legacy, err := PreviewUp(context.Background(), f.run, cfg, "castledrop", 72, []string{"gate:head"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.RoutesDir, legacy.RouteFile)
	before, _ := os.ReadFile(path)
	cfg.Knob.SharedDomain = "preview.avior.studio"
	if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 72, []string{"gate:head"}, previewNow); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing preview route was changed")
	}
}

func TestOldRecordKeepsLegacyHostnameAfterSharedOptIn(t *testing.T) {
	k, _ := ParsePreviewKnob("DOMAIN.prizm=preview.prizm.avior.studio\nSHARED_DOMAIN=preview.avior.studio\n")
	r := PreviewRecord{App: "prizm", PR: 72, Images: []string{"gate:head", "api:head"}}
	if r.WebHost(k) != "pr-72.preview.prizm.avior.studio" || r.PublicAPIHost(k) != "pr-72-api.preview.prizm.avior.studio" {
		t.Fatalf("old record moved without a deployment: %+v", r)
	}
}
