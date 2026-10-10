package workload

import (
	"strings"
	"testing"
)

func TestJSONImageReferencesKeepAllServicesWithoutEvaluation(t *testing.T) {
	refs, err := JSONImageReferences(strings.NewReader(`{"name":"app","services":{"gate":{"image":"ghcr.io/owner/app@sha256:123"},"ops":{"image":"ghcr.io/owner/ops:source","profiles":["ops"]}}}`))
	if err != nil || len(refs) != 2 || refs[1] != "ghcr.io/owner/ops:source" {
		t.Fatalf("profiled service omitted: %v %v", refs, err)
	}
	for _, bad := range []string{
		`{"services":{}}`,
		`{"services":{"api":{"build":"."}}}`,
		`{"services":{"api":{"image":"${FROM_ENV}"}}}`,
		`{"services":{"api":{"image":"one","image":"two"}}}`,
		`{"services":{"api":{"image":"one\ntwo"}}}`,
		`{"services":{"api":{"image":42}}}`,
		strings.Repeat("x", MaxBytes+1),
		`{"services":` + strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34) + `}`,
	} {
		if _, err := JSONImageReferences(strings.NewReader(bad)); err == nil {
			t.Fatalf("ambiguous or unresolved discovery accepted")
		}
	}
}
