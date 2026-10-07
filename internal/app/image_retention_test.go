package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

func TestAppImagePruneUsesOnlyTrustedTagsAndKeepsReferences(t *testing.T) {
	needs(t, "sh")
	needs(t, "flock")
	for _, tc := range []struct {
		name, record, live, fail string
		args                     []string
		wantRemoval              bool
		wantError                bool
	}{
		{"normal", "CURRENT=current\nPREVIOUS=rollback\n", "current", "", nil, true, false},
		{"dry run", "CURRENT=current\nPREVIOUS=rollback\n", "current", "", []string{"--dry-run"}, false, false},
		{"caller tags refused", "CURRENT=current\nPREVIOUS=rollback\n", "current", "", []string{"other", "old"}, false, true},
		{"caller family refused", "CURRENT=current\nPREVIOUS=rollback\n", "current", "", []string{"ghcr.io/you/other-"}, false, true},
		{"missing record", "", "current", "", nil, false, true},
		{"stale record", "CURRENT=current\nPREVIOUS=rollback\n", "different", "", nil, false, true},
		{"invalid tag", "CURRENT=current\nPREVIOUS=../other\n", "current", "", nil, false, true},
		{"duplicate key", "CURRENT=current\nCURRENT=rollback\n", "current", "", nil, false, true},
		{"container list fails", "CURRENT=current\nPREVIOUS=rollback\n", "current", "ps", nil, false, true},
		{"container inspect fails", "CURRENT=current\nPREVIOUS=rollback\n", "current", "inspect", nil, false, true},
		{"image list fails", "CURRENT=current\nPREVIOUS=rollback\n", "current", "images", nil, false, true},
		{"removal refused", "CURRENT=current\nPREVIOUS=rollback\n", "current", "image", nil, true, true},
		{"journal symlink refused", "symlink", "current", "", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(root, "docker.log")
			write(t, filepath.Join(bin, "docker"), 0o755, `#!/bin/sh
printf '%s\n' "$*" >> "$DOCKER_LOG"
[ -z "${DOCKER_HOST:-}${DOCKER_CONTEXT:-}${DOCKER_CONFIG:-}" ] || exit 3
[ "$1" != "$FAIL_DOCKER" ] || exit 1
case "$1" in
ps) [ "$*" = 'ps -aq' ] || exit 2; echo stopped ;;
inspect) [ "$*" = 'inspect --format {{.Image}} stopped' ] || exit 2; echo sha256:used ;;
images)
cat <<'IMAGES'
ghcr.io/you/blog-api current sha256:current
ghcr.io/you/blog-api rollback sha256:rollback
ghcr.io/you/blog-api alias-current sha256:current
ghcr.io/you/blog-api alias-rollback sha256:rollback
ghcr.io/you/blog-api old sha256:old
ghcr.io/you/blog-api stopped sha256:used
ghcr.io/you/blog-api <none> sha256:dangling
ghcr.io/you/blog2-api old sha256:other
ghcr.io/you/other-api old sha256:other
<none> <none> sha256:unknown
IMAGES
;;
image) [ "$*" = 'image rm ghcr.io/you/blog-api:old' ] || exit 2 ;;
*) exit 2 ;;
esac
`)
			write(t, filepath.Join(root, ".env"), 0o600, "APP_VERSION="+tc.live+"\n")
			if tc.record == "symlink" {
				write(t, filepath.Join(root, "untrusted"), 0o600, "CURRENT=current\nPREVIOUS=rollback\n")
				if err := os.Symlink(filepath.Join(root, "untrusted"), filepath.Join(root, ".komizo-image-retention")); err != nil {
					t.Fatal(err)
				}
			} else if tc.record != "" {
				write(t, filepath.Join(root, ".komizo-image-retention"), 0o600, tc.record)
			}
			body := between(t, scripts.AlpineScript, "<<'KOMIZO_PRUNE_EOF'\n", "KOMIZO_PRUNE_EOF\n")
			body = strings.NewReplacer("__APP_DIR__", root, "__CONFIG_IMAGE__", "ghcr.io/you/blog-config", "__APP_NAME__", "blog", "/run/komizo", filepath.Join(root, "run"), "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "PATH="+bin+":/usr/bin:/bin").Replace(body)
			program := filepath.Join(root, "prune-blog")
			write(t, program, 0o755, body)
			cmd := exec.Command("sh", append([]string{program}, tc.args...)...)
			cmd.Env = append(os.Environ(), "DOCKER_LOG="+log, "FAIL_DOCKER="+tc.fail, "DOCKER_HOST=untrusted", "DOCKER_CONTEXT=untrusted", "DOCKER_CONFIG=untrusted")
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantError {
				t.Fatalf("error %v, output %s", err, out)
			}
			calls, _ := os.ReadFile(log)
			gotRemoval := strings.Contains(string(calls), "image rm ")
			if gotRemoval != tc.wantRemoval {
				t.Fatalf("unexpected removal: %s\n%s", calls, out)
			}
			if tc.wantRemoval && strings.Count(string(calls), "image rm ") != 1 {
				t.Fatalf("protected image removed: %s", calls)
			}
			if !tc.wantError && !strings.Contains(string(out), "candidates=1") {
				t.Fatalf("protected aliases/references not retained: %s", out)
			}
		})
	}
}

func TestDeploymentRetentionRecordPreservesRollbackOnSameVersion(t *testing.T) {
	root := t.TempDir()
	body := between(t, scripts.AlpineScript, "# --- retention record begin ---\n", "# --- retention record end ---\n")
	run := func(version, previous string) {
		t.Helper()
		cmd := exec.Command("sh", "-s")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "version="+version, "previous="+previous)
		cmd.Stdin = strings.NewReader("set -eu\n" + body + "\nkomizo_record_image_retention\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	run("current", "rollback")
	path := filepath.Join(root, ".komizo-image-retention")
	want := "CURRENT=current\nPREVIOUS=rollback\n"
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("record %q, error %v", got, err)
	}
	run("current", "current")
	got, _ = os.ReadFile(path)
	if string(got) != want {
		t.Fatalf("same-version redeploy lost rollback: %q", got)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("retention record is not private: %v, %v", info, err)
	}
}

func TestPruneInstallerIsAppScopedAndRemovedWithApp(t *testing.T) {
	for _, required := range []string{
		`PRUNE_BIN="/usr/local/bin/prune-$APP_NAME"`,
		`permit nopass $CI_USER as root cmd $PRUNE_BIN`,
		`chown root:root "$PRUNE_BIN"`,
		`chmod 755 "$PRUNE_BIN"`,
		`recognised="$DEPLOY_BIN $PRUNE_BIN`,
	} {
		if !strings.Contains(scripts.AlpineScript, required) {
			t.Errorf("installer missing %s", required)
		}
	}
	if !strings.Contains(scripts.AlpineRemoveScript, `"$DEPLOY_BIN" "$PRUNE_BIN" "$SECRET_BIN"`) {
		t.Error("app removal leaves privileged prune command behind")
	}
}

func TestNightlyReclaimCallsScopedCommandsWithoutGlobalPrune(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "reclaim.log")
	calls := filepath.Join(root, "docker.log")
	write(t, filepath.Join(bin, "docker"), 0o755, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\n[ \"$*\" = info ]\n")
	write(t, filepath.Join(bin, "prune-ready"), 0o755, "#!/bin/sh\n[ $# = 0 ] || exit 1\necho 'retained current and rollback; removed one old image'\n")
	write(t, filepath.Join(bin, "prune-unready"), 0o755, "#!/bin/sh\necho 'trusted deployment record unavailable' >&2\nexit 1\n")
	body := between(t, scripts.AlpineInitScript, "<<'KOMIZO_RECLAIM_EOF'\n", "KOMIZO_RECLAIM_EOF\n")
	body = strings.NewReplacer("/var/log/komizo-reclaim.log", log, "/usr/local/bin", bin).Replace(body)
	cmd := exec.Command("sh", "-s")
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "DOCKER_LOG="+calls)
	cmd.Stdin = strings.NewReader(body)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nightly maintenance: %v, %s", err, out)
	}
	dockerCalls, err := os.ReadFile(calls)
	if err != nil || string(dockerCalls) != "info\n" {
		t.Fatalf("unexpected global Docker operation: %q, %v", dockerCalls, err)
	}
	record, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"prune-ready: retained current and rollback", "prune-unready: failed: trusted deployment record unavailable"} {
		if !strings.Contains(string(record), want) {
			t.Errorf("nightly result missing %q: %s", want, record)
		}
	}
}
