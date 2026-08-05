package box

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An app's directory is READ, never assumed.
//
// Assuming SrvDir/<name> is invisible to an app placed elsewhere with --app-dir,
// and the failure that produces is the worst kind: a lifecycle command that
// finds no compose file, does nothing, and has no reason to say so. The same
// argument appStates makes about globbing /srv.
func TestAppDirComesFromKomizosOwnRecord(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, AppsDir), 0o750); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(root, AppsDir, name+".env"), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	// Somewhere other than /srv/elsewhere, which is the case an assumption misses.
	write("elsewhere", "APP_NAME=elsewhere\nAPP_DIR=/opt/things/elsewhere\n")
	write("noplace", "APP_NAME=noplace\n")

	got, err := AppDir(root, "elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/opt/things/elsewhere" {
		t.Errorf("AppDir = %q, want the directory the record names", got)
	}

	if _, err := AppDir(root, "noplace"); err == nil {
		t.Error("a record with no APP_DIR was accepted, so komizo would act on a guess")
	}
	if _, err := AppDir(root, "neverheardof"); err == nil {
		t.Error("an app that does not exist was accepted")
	}
}

// A name is joined into a path, so a separator in one is refused rather than
// cleaned up. This is reached from a route on the internet in step 3.
func TestAppDirRefusesANameThatIsAPath(t *testing.T) {
	// A real apps directory, so the lookup is not what fails. Against a bare
	// temp dir every one of these also fails at readState, and the test passed
	// with the guard deleted.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, AppsDir), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "..", "../../etc", "a/b", "web.env", "./web"} {
		_, err := AppDir(root, bad)
		if err == nil || !strings.Contains(err.Error(), "is not an app name") {
			t.Errorf("AppDir(%q) = %v, want it refused as a name", bad, err)
		}
	}
}
