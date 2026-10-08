package box

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreviewACMEEmailIsOptionalAndScopedToPreview(t *testing.T) {
	record := PreviewRecord{App: "game", PR: 3, Project: "game-pr-3"}
	knob, note := ParsePreviewKnob("DOMAIN=preview.example.com\n")
	if note != "" || knob.ACMEEmail != "" {
		t.Fatalf("default knob changed: %+v, %q", knob, note)
	}
	want := "# Written by komizo preview. game PR #3 -- removed by 'komizo preview down'.\npr-3.preview.example.com, pr-3-api.preview.example.com {\n\treverse_proxy game-pr-3-gate:80\n}\n"
	if got := previewRoute(record, knob); got != want {
		t.Fatalf("unconfigured route changed:\n%s", got)
	}
	knob, note = ParsePreviewKnob("DOMAIN=preview.example.com\nACME_EMAIL=operator+previews@example.com\n")
	if note != "" || knob.ACMEEmail != "operator+previews@example.com" {
		t.Fatalf("email knob = %+v, %q", knob, note)
	}
	got := previewRoute(record, knob)
	if strings.Replace(got, "\ttls \"operator+previews@example.com\"\n", "", 1) != want {
		t.Fatalf("email must only add site-scoped TLS contact:\n%s", got)
	}
}

func TestPreviewRejectsInvalidACMEEmailBeforeChangingResources(t *testing.T) {
	for _, email := range []string{"invalid", "Operator <admin@example.com>", "admin@example.com\n}\n:443 { tls internal", "admin@example.com\x00"} {
		t.Run(email, func(t *testing.T) {
			cfg := previewTestConfig(t)
			cfg.Knob.ACMEEmail = email
			docker := &fakeDocker{}
			_, err := PreviewUp(context.Background(), docker.run, cfg, "game", 3, []string{"ghcr.io/owner/game-gate:revision"}, previewNow)
			if err == nil || !strings.Contains(err.Error(), "ACME_EMAIL") {
				t.Fatalf("invalid email accepted: %v", err)
			}
			if len(docker.calls) != 0 {
				t.Fatalf("invalid email touched Docker: %v", docker.calls)
			}
			if _, err := os.Stat(filepath.Join(cfg.Root, "game-pr-3")); !os.IsNotExist(err) {
				t.Fatalf("invalid email created preview state: %v", err)
			}
		})
	}
}
