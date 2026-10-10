package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func previewDBPolicyBody(t *testing.T, knob string) string {
	t.Helper()
	_, body, ok := strings.Cut(AlpineInitScript, "# BEGIN preview database memory policy\n")
	if !ok {
		t.Fatal("missing shipped preview database policy")
	}
	body, _, ok = strings.Cut(body, "# END preview database memory policy")
	if !ok {
		t.Fatal("missing policy end")
	}
	return strings.ReplaceAll(body, "/etc/komizo/preview", "'"+strings.ReplaceAll(knob, "'", "'\\''")+"'")
}

func TestPreviewDatabaseMemoryKnobFailsBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		valid            bool
	}{
		{"unset", "DOMAIN=preview.example.org\n", "256m", true},
		{"configured", "DB_MEM_LIMIT=192m\n", "192m", true},
		{"uppercase", "DB_MEM_LIMIT=1GB\r\n", "1gb", true},
		{"minimum", "DB_MEM_LIMIT=6m\n", "6m", true},
		{"maximum", "DB_MEM_LIMIT=64g\n", "64g", true},
		{"zero", "DB_MEM_LIMIT=0\n", "", false},
		{"empty", "DB_MEM_LIMIT=\n", "", false},
		{"tiny", "DB_MEM_LIMIT=5m\n", "", false},
		{"oversized", "DB_MEM_LIMIT=65g\n", "", false},
		{"overflow", "DB_MEM_LIMIT=999999999999999999g\n", "", false},
		{"injected", "DB_MEM_LIMIT=192m; echo bad\n", "", false},
		{"duplicate", "DB_MEM_LIMIT=192m\nDB_MEM_LIMIT=256m\n", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			knob := filepath.Join(t.TempDir(), "preview knob")
			if err := os.WriteFile(knob, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			body := "set -eu\ndie() { exit 19; }\n" + previewDBPolicyBody(t, knob) + "\nprintf '%s' \"$PREVIEW_DB_MEMORY\"\n"
			out, err := exec.Command("sh", "-c", body).CombinedOutput()
			if (err == nil) != tc.valid || (tc.valid && string(out) != tc.want) {
				t.Fatalf("valid=%v got %q %v", tc.valid, out, err)
			}
		})
	}
}

func TestPreviewDatabaseCapAppliesOnCreationAndReinit(t *testing.T) {
	for _, running := range []string{"true", "false"} {
		t.Run(running, func(t *testing.T) {
			dir := t.TempDir()
			knob := filepath.Join(dir, "preview")
			calls := filepath.Join(dir, "calls")
			if err := os.WriteFile(knob, []byte("DB_MEM_LIMIT=192m\n"), 0600); err != nil {
				t.Fatal(err)
			}
			_, body, ok := strings.Cut(AlpineInitScript, "PREVIEW_DB_IMAGE=")
			if !ok {
				t.Fatal("missing shipped provisioner")
			}
			body = "PREVIEW_DB_IMAGE=" + body
			body, _, ok = strings.Cut(body, "# Running is not accepting connections.")
			if !ok {
				t.Fatal("missing provisioner end")
			}
			harness := "set -eu\ndie() { exit 19; }\nlog() { :; }\nSHARED_NETWORK=edge\n" + previewDBPolicyBody(t, knob) + "\ndocker() { printf '%s\\n' \"$*\" >> \"$CALLS\"; if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then echo preview-database; elif [ \"$1\" = inspect ]; then echo \"$RUNNING\"; fi; }\n" + body
			cmd := exec.Command("sh", "-c", harness)
			cmd.Env = append(os.Environ(), "CALLS="+calls, "RUNNING="+running)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("shipped provisioning failed: %s %v", out, err)
			}
			out, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			text := string(out)
			if !strings.Contains(text, "update --memory 192m --memory-swap 192m --cpu-shares 128 --cpus 0.25 komizo-previews") {
				t.Fatal("re-init did not apply configured cap")
			}
			if running == "false" && (!strings.Contains(text, "run -d") || !strings.Contains(text, "--memory 192m --memory-swap 192m --cpu-shares 128 --cpus 0.25")) {
				t.Fatal("new container did not receive configured cap")
			}
			if running == "true" && strings.Contains(text, "rm -f") {
				t.Fatal("re-init replaced running preview database")
			}
		})
	}
}
