package devenv

import (
	"strings"
	"testing"
)

const testBundle = `{"version":1,"environment":"Preview","repository":"owner/repo","secrets":{"TOKEN":"synthetic secret"},"variables":{"URL":"http://localhost"}}`

func TestBundleScope(t *testing.T) {
	got, err := parsePreviewBundle([]byte(testBundle), "owner/repo")
	if err != nil || got.Secrets["TOKEN"] != "synthetic secret" {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	for _, data := range []string{
		"", "null", "{}", testBundle + testBundle,
		strings.Replace(testBundle, `"Preview"`, `"Production"`, 1),
		strings.Replace(testBundle, `"owner/repo"`, `"owner/other"`, 1),
		strings.Replace(testBundle, `"version":1`, `"version":2`, 1),
		strings.Replace(testBundle, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(testBundle, `"version":1`, `"version":1,"Version":1`, 1),
		strings.Replace(testBundle, `"version":1`, `"version":1,"unexpected":true`, 1),
		strings.Replace(testBundle, `"URL":"http://localhost"`, `"TOKEN":"duplicate"`, 1),
		strings.Replace(testBundle, `"TOKEN"`, `"GITHUB_TOKEN"`, 1),
		strings.Replace(testBundle, `"TOKEN"`, `"INVALID-NAME"`, 1),
		strings.Replace(testBundle, `"synthetic secret"`, `"bad\u0000value"`, 1),
		strings.Replace(testBundle, `"synthetic secret"`, `42`, 1),
		strings.Replace(testBundle, `"synthetic secret"`, `null`, 1),
		strings.Replace(testBundle, `"http://localhost"`, `null`, 1),
		strings.Replace(testBundle, `"secrets":{"TOKEN":"synthetic secret"}`, `"secrets":null`, 1),
		strings.Replace(testBundle, `"variables":{"URL":"http://localhost"}`, `"variables":null`, 1),
		strings.Replace(testBundle, `"secrets"`, `"ſecrets"`, 1),
		strings.Replace(testBundle, `"repository"`, `"repoſitory"`, 1),
		strings.Replace(testBundle, `"version":1`, `"Version":1`, 1),
		strings.Replace(testBundle, `"secrets":`, `"ſecrets":{"EXTRA":"sentinel"},"secrets":`, 1),
		strings.Replace(testBundle, `,"variables":{"URL":"http://localhost"}`, ``, 1),
		strings.Repeat(" ", maxBundle+1),
	} {
		if _, err := parsePreviewBundle([]byte(data), "owner/repo"); err == nil {
			t.Fatal("invalid or ambiguous bundle accepted")
		}
	}
	if _, err := parsePreviewBundle([]byte(testBundle), ""); err == nil {
		t.Fatal("accepted missing trusted workflow repository")
	}
}
