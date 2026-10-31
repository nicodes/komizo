package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The web tree carries no remnant of the stacks it replaced: no Clerk import,
// no PocketBase package, no env URL for either (the decommissioned backend),
// and no Expo / react-native / react-native-web import or package (the
// superseded RN-web export). Source-level, because what is pinned is an
// absence -- a reintroduced dependency fails here, wherever it lands.
func TestTheWebTreeHasNoRemnantsOfTheOldStacks(t *testing.T) {
	root := filepath.Join("..", "..", "ui")
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() && (name == "node_modules" || name == "dist") {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("the ui tree was not scanned -- has the layout changed?")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{
			"@clerk/", `"pocketbase"`, "EXPO_PUBLIC_PB_URL", "EXPO_PUBLIC_CLERK",
			"@expo/", `"expo"`, `"expo-`, `"react"`, `"react-dom"`, `"react-native`,
			`from "react`, `from 'react`, `from "expo`, `from 'expo`,
		} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s mentions %q -- a remnant of the decommissioned stack", f, banned)
			}
		}
	}

	// This test file and the comments in the Go source name the banned strings
	// to pin them; keep the scan to the web tree so the pins themselves pass.
}

// Every read the page consumes is a relative path to the same listener that
// served it -- no absolute URL, no second origin, no env-baked address.
func TestTheWebClientSpeaksOnlyToItsOwnOrigin(t *testing.T) {
	for _, f := range []string{"api.ts"} {
		src := sourceOf(t, filepath.Join("..", "..", "ui", "src", "lib", f))
		for _, banned := range []string{`"http://`, "`http://", `"https://`, "`https://", "EXPO_PUBLIC_"} {
			if strings.Contains(src, banned) {
				t.Errorf("ui/src/lib/%s contains %q -- the page must read only the box that served it", f, banned)
			}
		}
	}
}
