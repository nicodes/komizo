package app

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

func TestExplicitScopedAdaptersInstallWithNarrowModesAndKeepPrivateData(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	// Ownership is exercised by native root acceptance; record the requested owner
	// here so this fixture also runs on unprivileged hosted CI.
	if err := os.WriteFile(filepath.Join(bin, "chown"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	provision := filepath.Join(dir, "provision-mailroom")
	status := filepath.Join(dir, "status-mailroom")
	private := filepath.Join(dir, "existing-generation")
	if err := os.WriteFile(private, []byte("synthetic-existing-data"), 0600); err != nil {
		t.Fatal(err)
	}
	section := between(t, scripts.AlpineScript, "# --- 3b2. Operator-reviewed credential adapters -----------------------------\n", "# --- 3c. Named task path")
	section = strings.ReplaceAll(section, "/etc/periodic/15min/", dir+"/periodic/")
	section = strings.ReplaceAll(section, "/etc/local.d/", dir+"/local/")
	body := "#!/bin/sh\n# __APP_NAME__ __STATE_FILE__ __LOCK_FILE__\nexit 0\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	preamble := "set -eu\nAPP_NAME=mailroom\nSTATE_FILE=" + shQuote(filepath.Join(dir, "state.env")) + "\nSCOPED_ENV=mail-profile-v3\nSCOPED_SPEC_SET=1\nPROVISION_BIN=" + shQuote(provision) + "\nSTATUS_BIN=" + shQuote(status) + "\nSCOPED_BIN=" + shQuote(filepath.Join(dir, "obsolete")) + "\nSCOPED_PROVISION_B64=" + shQuote(encoded) + "\nSCOPED_STATUS_B64=" + shQuote(encoded) + "\ndie(){ echo refused >&2; exit 1; }\n"
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(preamble + section)
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install failed %v %s", err, out)
	}
	for path, mode := range map[string]os.FileMode{provision: 0700, status: 0755} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("wrong adapter mode", path, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || strings.Contains(string(got), "__APP_NAME__") || !strings.Contains(string(got), "mailroom") {
			t.Fatal("binding missing", err)
		}
	}
	if got, err := os.ReadFile(private); err != nil || string(got) != "synthetic-existing-data" {
		t.Fatal("credential data changed")
	}
}
