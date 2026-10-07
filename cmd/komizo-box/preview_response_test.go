package main

import (
	"encoding/json"
	"github.com/nicodes/komizo/box"
	"strings"
	"testing"
)

func TestPreviewUpResponseUsesRoutingDomainWithoutCredentials(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"DOMAIN=preview.default.dev\nDOMAIN.fieldsofrevik=preview.revik.gg\n", "preview.revik.gg"},
		{"DOMAIN=preview.default.dev\n", "preview.default.dev"},
		{"", box.PreviewDomainDefault},
	} {
		knob, _ := box.ParsePreviewKnob(tc.body)
		rec := box.PreviewRecord{App: "fieldsofrevik", PR: 326, DBPassword: "private-preview-password"}
		encoded, err := json.Marshal(previewUpResponse(rec, knob))
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(encoded, &result); err != nil {
			t.Fatal(err)
		}
		if result["domain"] != tc.want || result["app"] != rec.App || result["pr"] != float64(rec.PR) {
			t.Fatalf("incorrect public response: %s", encoded)
		}
		if _, ok := result["db_password"]; ok || strings.Contains(string(encoded), rec.DBPassword) {
			t.Fatal("public response exposes a credential")
		}
	}
}
