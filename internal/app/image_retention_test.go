package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// pruneFakeDocker answers the prune script's Docker calls for a family with
// tagged service images, retained config images and digest-pinned gate
// images, which Docker stores untagged.
const pruneFakeDocker = `#!/bin/sh
printf '%s\n' "$*" >> "$DOCKER_LOG"
[ -z "${DOCKER_HOST:-}${DOCKER_CONTEXT:-}${DOCKER_CONFIG:-}" ] || exit 3
[ "$1" != "$FAIL_DOCKER" ] || exit 1
case "$1" in
ps) [ "$*" = 'ps -aq' ] || exit 2; echo stopped; echo gatectr ;;
inspect)
	case "$*" in
	'inspect --format {{.Image}} stopped') echo sha256:used ;;
	'inspect --format {{.Image}} gatectr') echo sha256:gateused ;;
	*) exit 2 ;;
	esac ;;
images)
cat <<'IMAGES'
ghcr.io/you/blog-api current sha256:current
ghcr.io/you/blog-api rollback sha256:rollback
ghcr.io/you/blog-api alias-current sha256:current
ghcr.io/you/blog-api alias-rollback sha256:rollback
ghcr.io/you/blog-api old sha256:old
ghcr.io/you/blog-api stopped sha256:used
ghcr.io/you/blog-config current sha256:configcurrent
IMAGES
[ "$ROLLBACK_CONFIG" = absent ] || echo 'ghcr.io/you/blog-config rollback sha256:configrollback'
cat <<'IMAGES'
ghcr.io/you/blog-gate <none> sha256:gatecurrent
ghcr.io/you/blog-gate <none> sha256:gaterollback
ghcr.io/you/blog-gate <none> sha256:gateold
ghcr.io/you/blog-gate <none> sha256:gateold
ghcr.io/you/blog-gate <none> sha256:gateused
ghcr.io/you/blog-gate <none> sha256:current
ghcr.io/you/blog2-api old sha256:other
ghcr.io/you/other-api old sha256:other
<none> <none> sha256:unknown
IMAGES
;;
image)
	case "$2" in
	inspect)
		[ "$3" = --format ] || exit 2
		cat <<'NAMES'
sha256:configcurrent ghcr.io/you/blog-config:current ghcr.io/you/blog-config@sha256:configcurrent
sha256:configrollback ghcr.io/you/blog-config:rollback ghcr.io/you/blog-config@sha256:configrollback
sha256:current ghcr.io/you/blog-api:current ghcr.io/you/blog-api:alias-current ghcr.io/you/blog-api@sha256:current
sha256:gatecurrent ghcr.io/you/blog-gate@sha256:gatecurrent
sha256:gaterollback ghcr.io/you/blog-gate@sha256:gaterollback
sha256:gateold ghcr.io/you/blog-gate@sha256:gateold
sha256:gateused ghcr.io/you/blog-gate@sha256:gateused
sha256:old ghcr.io/you/blog-api:old ghcr.io/you/blog-api@sha256:old
sha256:other ghcr.io/you/blog2-api:old ghcr.io/you/other-api:old
sha256:rollback ghcr.io/you/blog-api:rollback ghcr.io/you/blog-api:alias-rollback
sha256:unknown
sha256:used ghcr.io/you/blog-api:stopped
NAMES
		;;
	rm)
		case "$*" in
		'image rm ghcr.io/you/blog-api:old'|'image rm sha256:gateold') ;;
		*) exit 2 ;;
		esac ;;
	*) exit 2 ;;
	esac ;;
create)
	[ "$*" = 'create --pull never --entrypoint /nonexistent ghcr.io/you/blog-config:rollback' ] || exit 2
	echo reader ;;
cp)
	[ "$2" = reader:/config/compose.yml ] || exit 2
	case "$ROLLBACK_CONFIG" in
	unreadable) exit 1 ;;
	symlink) ln -s /etc/passwd "$3" ;;
	variable) printf 'services:\n  gate:\n    image: ghcr.io/you/blog-gate:${GATE_TAG}\n' > "$3" ;;
	*) printf 'services:\n  gate:\n    image: "ghcr.io/you/blog-gate@sha256:gaterollback" # pinned\n  api:\n    image: ghcr.io/you/blog-api:${APP_VERSION:?release}\n' > "$3" ;;
	esac ;;
rm) [ "$*" = 'rm -v reader' ] || exit 2 ;;
*) exit 2 ;;
esac
`

func TestAppImagePruneUsesOnlyTrustedTagsAndKeepsReferences(t *testing.T) {
	needs(t, "sh")
	needs(t, "flock")
	const record = "CURRENT=current\nPREVIOUS=rollback\n"
	const pinned = "services:\n  gate:\n    image: ghcr.io/you/blog-gate:tag@sha256:gatecurrent\n  api:\n    image: 'ghcr.io/you/blog-api:${APP_VERSION}'\n"
	tagged, untagged := "image rm ghcr.io/you/blog-api:old", "image rm sha256:gateold"
	for _, tc := range []struct {
		name, record, live, fail, compose, rollback string
		args                                        []string
		wantRemoved                                 []string
		wantError                                   bool
		wantOutput                                  string
	}{
		{name: "normal", record: record, live: "current", wantRemoved: []string{tagged, untagged}, wantOutput: "candidates=2 removed=2"},
		{name: "dry run lists untagged", record: record, live: "current", args: []string{"--dry-run"}, wantOutput: "prune: would remove ghcr.io/you/blog-gate (untagged sha256:gateold)"},
		{name: "rollback config absent retains untagged", record: record, live: "current", rollback: "absent", wantRemoved: []string{tagged}, wantOutput: "untagged images retained"},
		{name: "first deployment has no rollback to keep", record: "CURRENT=current\nPREVIOUS=\n", live: "current", args: []string{"--dry-run"}, wantOutput: "candidates=6"},
		{name: "rollback compose unreadable", record: record, live: "current", rollback: "unreadable", wantError: true},
		{name: "rollback compose symlink", record: record, live: "current", rollback: "symlink", wantError: true},
		{name: "rollback compose unresolvable", record: record, live: "current", rollback: "variable", wantError: true},
		{name: "current compose unresolvable", record: record, live: "current", compose: "services:\n  gate:\n    image: ${GATE}\n", wantError: true},
		{name: "current compose missing", record: record, live: "current", compose: "missing", wantError: true},
		{name: "caller tags refused", record: record, live: "current", args: []string{"other", "old"}, wantError: true},
		{name: "caller family refused", record: record, live: "current", args: []string{"ghcr.io/you/other-"}, wantError: true},
		{name: "missing record", live: "current", wantError: true},
		{name: "stale record", record: record, live: "different", wantError: true},
		{name: "invalid tag", record: "CURRENT=current\nPREVIOUS=../other\n", live: "current", wantError: true},
		{name: "duplicate key", record: "CURRENT=current\nCURRENT=rollback\n", live: "current", wantError: true},
		{name: "container list fails", record: record, live: "current", fail: "ps", wantError: true},
		{name: "container inspect fails", record: record, live: "current", fail: "inspect", wantError: true},
		{name: "image list fails", record: record, live: "current", fail: "images", wantError: true},
		{name: "rollback reader fails", record: record, live: "current", fail: "create", wantError: true},
		{name: "removal refused", record: record, live: "current", fail: "image", wantError: true},
		{name: "journal symlink refused", record: "symlink", live: "current", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(root, "docker.log")
			write(t, filepath.Join(bin, "docker"), 0o755, pruneFakeDocker)
			write(t, filepath.Join(root, ".env"), 0o600, "APP_VERSION="+tc.live+"\n")
			switch tc.compose {
			case "":
				write(t, filepath.Join(root, "compose.yml"), 0o600, pinned)
			case "missing":
			default:
				write(t, filepath.Join(root, "compose.yml"), 0o600, tc.compose)
			}
			if tc.record == "symlink" {
				write(t, filepath.Join(root, "untrusted"), 0o600, record)
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
			cmd.Env = append(os.Environ(), "DOCKER_LOG="+log, "FAIL_DOCKER="+tc.fail, "ROLLBACK_CONFIG="+tc.rollback, "DOCKER_HOST=untrusted", "DOCKER_CONTEXT=untrusted", "DOCKER_CONFIG=untrusted")
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantError {
				t.Fatalf("error %v, output %s", err, out)
			}
			raw, _ := os.ReadFile(log)
			calls := string(raw)
			var got []string
			for _, line := range strings.Split(calls, "\n") {
				if strings.HasPrefix(line, "image rm ") {
					got = append(got, line)
				}
			}
			want := tc.wantRemoved
			if tc.name == "removal refused" {
				want = nil // the fake refuses every removal before logging success
			}
			if tc.name != "removal refused" && strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("removals %q, want %q\n%s", got, want, out)
			}
			if tc.wantError && tc.name != "removal refused" && len(got) != 0 {
				t.Fatalf("a refusal still removed images: %q", got)
			}
			if tc.fail != "create" && strings.Contains(calls, "create ") && !strings.Contains(calls, "rm -v reader") {
				t.Fatalf("rollback config reader left behind: %s", calls)
			}
			if !strings.Contains(string(out), tc.wantOutput) {
				t.Fatalf("output missing %q: %s", tc.wantOutput, out)
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
	write(t, filepath.Join(bin, "docker"), 0o755, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\n[ \"$*\" = 'info --format {{.DockerRootDir}}' ] && echo /var/lib/docker\n")
	// 1 GiB free on the Docker root: under the warning threshold.
	write(t, filepath.Join(bin, "df"), 0o755, "#!/bin/sh\n[ \"$*\" = '-Pk /var/lib/docker' ] || exit 1\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\necho '/dev/vda2 25000000 23951424 1048576 96% /var/lib/docker'\n")
	write(t, filepath.Join(bin, "logger"), 0o755, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SYSLOG\"\n")
	write(t, filepath.Join(bin, "prune-ready"), 0o755, "#!/bin/sh\n[ $# = 0 ] || exit 1\necho 'retained current and rollback; removed one old image'\n")
	write(t, filepath.Join(bin, "prune-unready"), 0o755, "#!/bin/sh\necho 'trusted deployment record unavailable' >&2\nexit 1\n")
	body := between(t, scripts.AlpineInitScript, "<<'KOMIZO_RECLAIM_EOF'\n", "KOMIZO_RECLAIM_EOF\n")
	body = strings.NewReplacer("/var/log/komizo-reclaim.log", log, "/usr/local/bin", bin).Replace(body)
	cmd := exec.Command("sh", "-s")
	syslog := filepath.Join(root, "syslog")
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "DOCKER_LOG="+calls, "SYSLOG="+syslog)
	cmd.Stdin = strings.NewReader(body)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nightly maintenance: %v, %s", err, out)
	}
	dockerCalls, err := os.ReadFile(calls)
	if err != nil || string(dockerCalls) != "info --format {{.DockerRootDir}}\n" {
		t.Fatalf("unexpected global Docker operation: %q, %v", dockerCalls, err)
	}
	record, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"prune-ready: retained current and rollback", "prune-unready: failed: trusted deployment record unavailable", "WARNING: low disk: 1024 MiB free under /var/lib/docker"} {
		if !strings.Contains(string(record), want) {
			t.Errorf("nightly result missing %q: %s", want, record)
		}
	}
	if warned, _ := os.ReadFile(syslog); !strings.Contains(string(warned), "-t komizo-reclaim WARNING: low disk") {
		t.Errorf("low disk not sent to syslog: %q", warned)
	}
}
