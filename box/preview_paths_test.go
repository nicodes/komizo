package box

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathPreviewsShareHostButKeepIndependentRoutes(t *testing.T) {
	cfg := previewTestConfig(t)
	cfg.Knob, _ = ParsePreviewKnob("PATH_DOMAIN.prizm=preview.avior.studio\n")
	f := &fakeDocker{}
	var records []PreviewRecord
	for _, pr := range []int{72, 73} {
		rec, err := PreviewUp(context.Background(), f.run, cfg, "prizm", pr, []string{"gate:head"}, previewNow)
		if err != nil {
			t.Fatal(err)
		}
		target, err := ResolvePreview(cfg.Knob, "prizm", pr, false)
		if err != nil || rec.Host != "prizm.preview.avior.studio" || rec.BasePath != target.BasePath || rec.APIHost != "" {
			t.Fatalf("wrong target: %+v %+v %v", rec, target, err)
		}
		route, err := os.ReadFile(filepath.Join(cfg.RoutesDir, rec.RouteFile))
		if err != nil || !strings.Contains(string(route), "handle_path "+rec.BasePath+"/*") || !strings.Contains(string(route), rec.Project+"-gate:80") {
			t.Fatalf("wrong route: %s %v", route, err)
		}
		stored, err := readPreviewRecord(previewDir(cfg.Root, rec.Project))
		if err != nil || stored.BasePath != rec.BasePath {
			t.Fatal("path not persisted", err)
		}
		compose, _ := os.ReadFile(filepath.Join(previewDir(cfg.Root, rec.Project), "compose.yml"))
		if !strings.Contains(string(compose), "BASE_URL: https://prizm.preview.avior.studio"+rec.BasePath) {
			t.Fatal(string(compose))
		}
		records = append(records, rec)
	}
	sitePath := filepath.Join(cfg.RoutesDir, "_preview-path-prizm.caddy")
	site, err := os.ReadFile(sitePath)
	if err != nil || strings.Count(string(site), "prizm.preview.avior.studio") != 1 || strings.Contains(string(site), "-api.") {
		t.Fatalf("%s: %v", site, err)
	}
	secondPath := filepath.Join(cfg.RoutesDir, records[1].RouteFile)
	before, _ := os.ReadFile(secondPath)
	if err := PreviewDown(context.Background(), f.run, cfg, records[0]); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(secondPath)
	if string(before) != string(after) {
		t.Fatal("closing one PR changed its sibling")
	}
	if _, err := os.Stat(filepath.Join(cfg.RoutesDir, records[0].RouteFile)); !os.IsNotExist(err) {
		t.Fatal("closed PR route remains")
	}
	if _, err := os.Stat(sitePath); err != nil {
		t.Fatal("stable host removed with PR", err)
	}
}

func TestPathPreviewAPIAndAuthorization(t *testing.T) {
	k, _ := ParsePreviewKnob("PATH_DOMAIN.prizm=preview.avior.studio\n")
	target, err := ResolvePreview(k, "prizm", 72, true)
	if err != nil || target.Host != "prizm.preview.avior.studio" || target.APIHost != "prizm-api.preview.avior.studio" || target.BasePath != "/72" {
		t.Fatalf("%+v %v", target, err)
	}
	for _, host := range []string{target.Host, target.APIHost} {
		if !k.PathAskAllow(host) {
			t.Error("refused", host)
		}
	}
	for _, host := range []string{"other.preview.avior.studio", "prizm-pr72.preview.avior.studio", "prizm.preview.avior.studio.evil.example"} {
		if k.PathAskAllow(host) {
			t.Error("authorized", host)
		}
	}
	legacy, err := ResolvePreview(k, "castledrop", 72, false)
	if err != nil || legacy.BasePath != "" || legacy.Host != "pr-72.preview.gdam.dev" {
		t.Fatalf("legacy changed: %+v %v", legacy, err)
	}
}

func TestPathSiteAndHandlerRestoreOnValidationFailure(t *testing.T) {
	cfg := previewTestConfig(t)
	cfg.Knob, _ = ParsePreviewKnob("PATH_DOMAIN.prizm=preview.avior.studio\n")
	f := &fakeDocker{validateErr: errors.New("invalid config")}
	rec := PreviewRecord{App: "prizm", PR: 72, Project: "prizm-pr-72", Host: "prizm.preview.avior.studio", BasePath: "/72", RouteFile: "_preview-pr-72.prizm.route", Images: []string{"gate:head"}}
	if err := applyPreviewRecordRoute(context.Background(), f.run, cfg, rec); err == nil {
		t.Fatal("validation failure accepted")
	}
	for _, file := range []string{rec.RouteFile, "_preview-path-prizm.caddy"} {
		if _, err := os.Stat(filepath.Join(cfg.RoutesDir, file)); !os.IsNotExist(err) {
			t.Fatal("failed route left behind", file, err)
		}
	}
}
