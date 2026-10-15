package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func renderScoped(t *testing.T, body, appDir, stateFile, lock string) string {
	t.Helper()
	return strings.NewReplacer(
		"__APP_NAME__", "fieldsofrevik",
		"__STATE_FILE__", stateFile,
		"__LOCK_FILE__", lock,
	).Replace(body)
}

func writeState(t *testing.T, path, appDir string) {
	t.Helper()
	body := "APP_NAME=fieldsofrevik\nAPP_DIR=" + appDir + "\nSCOPED_ENV=fields-postgres-v2\n"
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func writeClerk(t *testing.T, path, parties string) {
	t.Helper()
	body := "CLERK_ISSUER=https://clerk.example\nCLERK_JWKS_URL=https://clerk.example/jwks\nCLERK_AUTHORIZED_PARTIES=" + parties + "\nCLERK_SECRET_KEY=" + clerkSecretFixture + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const clerkSecretFixture = "sk_live_ExampleKey123"

func v2EnvFixture(name string) string {
	switch name {
	case "postgres.env":
		return "POSTGRES_PASSWORD=x\nREVIK_MIGRATOR_PASSWORD=x\nREVIK_APP_PASSWORD=x\nREVIK_BACKUP_PASSWORD=x\n"
	case "migrate.env":
		return "DATABASE_MIGRATION_URL=x\n"
	case "api.env":
		return "DATABASE_URL=x\nWS_SECRET=x\nCLERK_ISSUER=https://clerk.example\nCLERK_JWKS_URL=https://clerk.example/jwks\nCLERK_AUTHORIZED_PARTIES=https://app.example\nCLERK_SECRET_KEY=sk_live_deployfixture\n"
	case "godot-api.env":
		return "WS_SECRET=x\n"
	default:
		return ""
	}
}

func writeCompose(t *testing.T, appDir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(appDir, "compose.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const placeholderCompose = "services: {}\n"

const pbCompose = `services:
  db:
    image: pb:1
    volumes: [pb_data:/pb/pb_data]
volumes:
  pb_data:
`

const pgCompose = `services:
  postgres:
    image: postgres:16
    env_file: [./secrets/current/postgres.env]
    volumes: [pg_data:/var/lib/postgresql/data]
  migrate:
    image: migrate:1
    env_file: [./secrets/current/migrate.env]
  api:
    image: api:1
    env_file: [./secrets/current/api.env]
  godot-api:
    image: godot:1
    env_file: [./secrets/current/godot-api.env]
volumes:
  pg_data:
`

func dockerStub(mount string) string {
	docker, err := exec.LookPath("docker")
	if err != nil {
		docker = "/usr/bin/docker"
	}
	return "#!/bin/sh\nreal=" + shellQuote(docker) + "\n" + `if [ "$1" = "compose" ]; then
  exec "$real" "$@"
fi
if [ "$1" = "ps" ]; then
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
  if [ -n "$STUB_MOUNT" ]; then
    printf 'local %s\n' "$STUB_MOUNT"
    exit 0
  fi
  echo "no such volume" >&2
  exit 1
fi
echo "unexpected docker $*" >&2
exit 1
`
}

func writeRootStubs(t *testing.T, bin string) {
	t.Helper()
	writeStub(t, bin, "id", "#!/bin/sh\nif [ \"$1\" = \"-u\" ]; then echo 0; exit 0; fi\nexit 0\n")
	writeStub(t, bin, "chown", "#!/bin/sh\nexit 0\n")
	writeStub(t, bin, "stat", "#!/bin/sh\nfmt=\nfile=\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -c) fmt=$2; shift 2 ;;\n    *) file=$1; shift ;;\n  esac\ndone\nif [ \"$fmt\" = \"%u\" ]; then echo 0; exit 0; fi\nif [ \"$fmt\" = \"%a\" ] || [ \"$fmt\" = \"%s\" ]; then\n  /usr/bin/stat -c \"$fmt\" \"$file\"\n  exit 0\nfi\nif [ -d \"$file\" ]; then echo 700; else echo 600; fi\n")
}

func scopedPaths(t *testing.T) (root, appDir, stateFile, lock, bin string) {
	t.Helper()
	root = t.TempDir()
	appDir = filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stateFile = filepath.Join(root, "fieldsofrevik.env")
	lock = filepath.Join(root, "deploy.lock")
	bin = filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStub(t, bin, "docker", dockerStub(""))
	writeRootStubs(t, bin)
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	return root, appDir, stateFile, lock, bin
}

func runScript(t *testing.T, path string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return string(out), code
}

func TestLegacyMigrationComparesExpectedGeneration(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRootStubs(t, bin)
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	const start = "komizo_scoped_env_ready() {"
	const end = "# Operator-written host-wide floors"
	source := legacyDeployBody(t)
	i := strings.Index(source, start)
	j := strings.Index(source, end)
	if i < 0 || j < i {
		t.Fatal("deploy preflight function was not found")
	}
	fn := source[i:j]
	app := filepath.Join(dir, "app")
	id := "0123456789abcdef0123456789abcdef"
	gen := filepath.Join(app, "secrets", "generations", id)
	if err := os.MkdirAll(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"postgres.env", "migrate.env", "api.env", "godot-api.env"} {
		if err := os.WriteFile(filepath.Join(gen, name), []byte(v2EnvFixture(name)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(gen, "provenance"), []byte("profile=fields-postgres-v2\nschema=11\ngeneration="+id+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("generations/"+id, filepath.Join(app, "secrets", "current")); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "app.env")
	if err := os.WriteFile(state, []byte("APP_DIR="+app+"\nSCOPED_GENERATION="+id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "set -eu\nAPP_DIR=" + shellQuote(app) + "\nSTATE_FILE=" + shellQuote(state) + "\nexpected_generation=" + id + "\n" + fn + "\nkomizo_scoped_env_ready\n"
	ready := script
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("matching generation refused: %v\n%s", err, out)
	}
	script = strings.Replace(script, "expected_generation="+id, "expected_generation=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
	cmd = exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "scoped generation mismatch") {
		t.Fatalf("mismatch should refuse, err=%v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(gen, "api.env"), []byte("CLERK_SECRET_KEY=sk_live_deployfixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(ready)
	out, err = cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "sk_live_deployfixture") {
		t.Fatalf("deploy read env bytes: %v\n%s", err, out)
	}
	if err := os.Remove(filepath.Join(gen, "provenance")); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(ready)
	out, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "not a fields-postgres-v2 generation") || strings.Contains(string(out), "sk_live_deployfixture") {
		t.Fatal("generation without provenance was accepted or printed")
	}
	const startFn = "komizo_scoped_env_ready() {"
	fnStart := strings.Index(source, startFn)
	fnEnd := strings.Index(source, "# Operator-written host-wide floors")
	if fnStart < 0 || fnEnd < fnStart || strings.Contains(source[fnStart:fnEnd], "CLERK_SECRET_KEY") {
		t.Fatal("deploy preflight still names a secret")
	}
}

func TestShippedDeployArgvContract(t *testing.T) {
	for _, want := range []string{
		"deploy: scoped generation missing",
		"deploy: unexpected arguments",
		"--generation \"${4:-}\"",
		"workload deployment-submit --policy",
		"exec komizo-box workload activation-wait --id",
	} {
		if !strings.Contains(AlpineScript, want) {
			t.Errorf("shipped deploy script missing %q", want)
		}
	}
	if strings.Contains(AlpineScript, "stage|confirm|abort") {
		t.Fatal("shipped script still advertises the withdrawn stage protocol")
	}
	if strings.Contains(AlpineScript, "permit nopass $CI_USER as root cmd $SCOPED_BIN") {
		t.Fatal("doas still grants the setter binary")
	}
}

func TestRemoveKeepDataLeavesScopedSecrets(t *testing.T) {
	// The shell gate fails the image if any ./scripts test skips. The source
	// contract is always checked. The mount proof runs only where it can.
	body, err := os.ReadFile("alpine-remove.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		`rm -f "$DEPLOY_BIN" "$PRUNE_BIN" "$SECRET_BIN" "$RELEASE_SECRETS_BIN" "$TASK_BIN" "$SCOPED_BIN" "$PROVISION_BIN" "$STATUS_BIN"`,
		"KEEP_DATA leaves $APP_DIR, including secrets/",
		"KEEP_DATA does not keep the binaries",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("alpine-remove.sh missing %q", want)
		}
	}
	if os.Getuid() != 0 {
		return
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		return
	}
	root := t.TempDir()
	app := filepath.Join(root, "app")
	secret := filepath.Join(app, "secrets", "current")
	if err := os.MkdirAll(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "api.env"), []byte("WS_SECRET=keep-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "usr-local-bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"set-scoped-env-fieldsofrevik", "provision-scoped-env-fieldsofrevik", "scoped-env-status-fieldsofrevik"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	etc := filepath.Join(root, "etc")
	periodic := filepath.Join(etc, "periodic", "15min")
	locald := filepath.Join(etc, "local.d")
	if err := os.MkdirAll(periodic, 0o755); err != nil || os.MkdirAll(locald, 0o755) != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(periodic, "komizo-scoped-env-fieldsofrevik")
	boot := filepath.Join(locald, "komizo-scoped-env-fieldsofrevik.start")
	for _, path := range []string{helper, boot} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{
		filepath.Join(root, "var-komizo", "apps"),
		filepath.Join(root, "srv"),
		filepath.Join(root, "ssh"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := "set -eu\n" +
		"mkdir -p /usr/local/bin /etc /var/lib/komizo /srv\n" +
		"mount --bind " + shellQuote(bin) + " /usr/local/bin\n" +
		"mount --bind " + shellQuote(etc) + " /etc\n" +
		"mount --bind " + shellQuote(filepath.Join(root, "var-komizo")) + " /var/lib/komizo\n" +
		"mount --bind " + shellQuote(filepath.Join(root, "srv")) + " /srv\n" +
		"export APP_NAME=fieldsofrevik\n" +
		"export APP_DIR=" + shellQuote(app) + "\n" +
		"export CI_USER=komizo-scoped-env-keep\n" +
		"export KEEP_DATA=1\n" +
		"sh " + shellQuote("alpine-remove.sh") + "\n"
	cmd := exec.Command("unshare", "--mount", "sh", "-s")
	cmd.Dir = "."
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Dir = wd
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("KEEP_DATA removal failed: %v\n%s", err, out)
	}
	for _, name := range []string{"set-scoped-env-fieldsofrevik", "provision-scoped-env-fieldsofrevik", "scoped-env-status-fieldsofrevik"} {
		if _, err := os.Stat(filepath.Join(bin, name)); !os.IsNotExist(err) {
			t.Fatalf("KEEP_DATA left %s installed", name)
		}
	}
	if _, err := os.Stat(helper); !os.IsNotExist(err) {
		t.Fatal("KEEP_DATA left the periodic helper")
	}
	got, err := os.ReadFile(filepath.Join(secret, "api.env"))
	if err != nil || string(got) != "WS_SECRET=keep-me\n" {
		t.Fatalf("KEEP_DATA changed secrets: %q %v", got, err)
	}
}
