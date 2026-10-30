package agent

import (
	"os"
	"strings"
	"testing"
)

// Installation guidance uses published binaries for both supported methods.
func TestTheReadmeShowsBothBinaryInstallMethods(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	curl := strings.Index(readme, "curl -fsSL https://komizo.dev/install | sh")
	mise := strings.Index(readme, "mise use --global github:nicodes/komizo@latest")
	if curl < 0 || mise < 0 {
		t.Fatal("README must show the curl and mise binary installation methods")
	}
	if mise < curl {
		t.Error("README must show curl before mise")
	}
	for _, sourceInstall := range []string{"go run github.com/nicodes/komizo@", "go install github.com/nicodes/komizo@", "gh release download"} {
		if strings.Contains(readme, sourceInstall) {
			t.Errorf("README advertises an extra installation alternative: %s", sourceInstall)
		}
	}
}

// AND THE FAILURE THAT REMAINS NAMES A REMEDY THE READER CAN TAKE.
//
// There is still one case with no agent and no way to get one: a build with no
// module version to pin -- a checkout, or VCS stamping turned off. "Run `make
// agents`" is the right advice there, because that reader HAS a checkout.
func TestTheRemainingFailureNamesARemedyTheReaderCanTake(t *testing.T) {
	_, err := For("no-such-arch")
	if err == nil {
		t.Fatal("an architecture komizo does not ship returned an agent")
	}
	if !strings.Contains(err.Error(), "mise run agents") {
		t.Errorf("the missing-agent error does not name the remedy:\n%s", err)
	}
}
