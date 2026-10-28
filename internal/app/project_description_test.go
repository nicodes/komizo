package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nicodes/komizo/internal/project"
)

func TestHumanDescribeDisplaysProjectCapabilities(t *testing.T) {
	dir := t.TempDir()
	if _, err := project.Init(dir, "configuration", versionText()); err != nil {
		t.Fatal(err)
	}
	var out, progress bytes.Buffer
	handled, code := ProjectCommand([]string{"describe", "--directory", dir}, strings.NewReader(""), &out, &progress)
	if !handled || code != 0 {
		t.Fatalf("describe refused: %s", progress.String())
	}
	for _, want := range []string{"Recipe: configuration", "Platform: komizo", "Tools:", "python 3.13.11", "Stages:", "Commands:", "komizo check"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q: %s", want, out.String())
		}
	}
}
