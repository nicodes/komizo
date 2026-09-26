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

func TestProvisionWritesTenValuesOnceAndDoesNotEchoThem(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	_, appDir, stateFile, lock, _ := scopedPaths(t)
	writeState(t, stateFile, appDir)
	live := "services:\n  db:\n    image: pb:1\n"
	writeCompose(t, appDir, live)
	if err := os.WriteFile(filepath.Join(appDir, "secrets.env"), []byte("POCKETBASE_ADMIN_PASSWORD=leave-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(t.TempDir(), "candidate.yml")
	if err := os.WriteFile(candidate, []byte(pgCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	clerk := filepath.Join(t.TempDir(), "clerk")
	writeClerk(t, clerk, "https://app.example")
	script := renderScoped(t, fieldsScopedEnvBody, appDir, stateFile, lock)
	path := filepath.Join(t.TempDir(), "provision")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, path, nil, "--clerk-file", clerk, "--compose-file", candidate)
	if code != 0 {
		t.Fatalf("provision failed: %s", out)
	}
	if strings.Contains(out, "https://clerk.example") || strings.Contains(out, "leave-me") {
		t.Fatalf("provision echoed a value:\n%s", out)
	}
	if !strings.HasPrefix(out, "generation=") || strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout = %q", out)
	}
	id := strings.TrimPrefix(strings.TrimSpace(out), "generation=")
	if len(id) != 32 {
		t.Fatalf("id %q", id)
	}
	if _, err := os.Stat(clerk); !os.IsNotExist(err) {
		t.Fatal("clerk file was not removed")
	}
	kept, err := os.ReadFile(filepath.Join(appDir, "secrets.env"))
	if err != nil || string(kept) != "POCKETBASE_ADMIN_PASSWORD=leave-me\n" {
		t.Fatalf("secrets.env changed: %q %v", kept, err)
	}
	gotLive, err := os.ReadFile(filepath.Join(appDir, "compose.yml"))
	if err != nil || string(gotLive) != live {
		t.Fatalf("live compose changed: %q %v", gotLive, err)
	}
	link, err := os.Readlink(filepath.Join(appDir, "secrets", "current"))
	if err != nil || link != "generations/"+id {
		t.Fatalf("current link %q %v", link, err)
	}
	api, err := os.ReadFile(filepath.Join(appDir, "secrets", "generations", id, "api.env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, string(api)) {
		t.Fatal("stdout contains api.env")
	}
	for _, key := range []string{"DATABASE_URL=", "WS_SECRET=", "CLERK_ISSUER=https://clerk.example", "CLERK_JWKS_URL=https://clerk.example/jwks", "CLERK_AUTHORIZED_PARTIES=https://app.example"} {
		if !strings.Contains(string(api), key) {
			t.Fatalf("api.env missing %s", key)
		}
	}
	if !strings.Contains(string(api), "CLERK_SECRET_KEY="+clerkSecretFixture+"\n") {
		t.Fatal("api.env missing production key")
	}
	if strings.Contains(out, clerkSecretFixture) {
		t.Fatal("stdout contains the production key")
	}
	for _, name := range []string{"postgres.env", "migrate.env", "godot-api.env"} {
		body, err := os.ReadFile(filepath.Join(appDir, "secrets", "generations", id, name))
		if err != nil || strings.Contains(string(body), "CLERK_SECRET_KEY") {
			t.Fatalf("%s is not confined to api.env", name)
		}
	}
	if !strings.Contains(string(api), "@postgres/revik?sslmode=disable") {
		t.Fatal("dsn shape drifted")
	}
	markerPath := filepath.Join(appDir, "secrets", "generations", id, "provenance")
	marker, err := os.ReadFile(markerPath)
	wantMarker := "profile=fields-postgres-v2\nschema=11\ngeneration=" + id + "\n"
	if err != nil || string(marker) != wantMarker || strings.Contains(out, wantMarker) {
		t.Fatalf("provenance %q err=%v", marker, err)
	}
	info, err := os.Stat(markerPath)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("provenance mode %v %v", info, err)
	}
	rec, err := os.ReadFile(stateFile)
	if err != nil || !strings.Contains(string(rec), "SCOPED_GENERATION="+id+"\n") {
		t.Fatalf("record missing generation: %s", rec)
	}
	again, code := runScript(t, path, nil, "--compose-file", candidate)
	if code == 0 || !strings.Contains(again, "already exists") {
		t.Fatalf("second provision code %d\n%s", code, again)
	}
}

func TestProvisionRefusesInitializedPostgresAndLeavesPocketBase(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	_, appDir, stateFile, lock, _ := scopedPaths(t)
	writeState(t, stateFile, appDir)
	mount := filepath.Join(t.TempDir(), "pg")
	if err := os.MkdirAll(mount, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, "PG_VERSION"), []byte("16\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCompose(t, appDir, pgCompose)
	clerk := filepath.Join(t.TempDir(), "clerk")
	writeClerk(t, clerk, "https://app.example")
	candidate := filepath.Join(t.TempDir(), "candidate.yml")
	if err := os.WriteFile(candidate, []byte(pgCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	script := renderScoped(t, fieldsScopedEnvBody, appDir, stateFile, lock)
	path := filepath.Join(t.TempDir(), "provision")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, path, []string{"STUB_MOUNT=" + mount}, "--clerk-file", clerk, "--compose-file", candidate)
	if code == 0 || !strings.Contains(out, "already initialized") {
		t.Fatalf("initialized volume should refuse, code %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(appDir, "secrets", "generations")); !os.IsNotExist(err) {
		t.Fatal("initialized volume wrote a generation")
	}

	pbMount := filepath.Join(t.TempDir(), "pb")
	if err := os.MkdirAll(pbMount, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pbMount, "data.db"), []byte("pocketbase"), 0o600); err != nil {
		t.Fatal(err)
	}
	pbDir := filepath.Join(t.TempDir(), "pbapp")
	if err := os.MkdirAll(pbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeState(t, stateFile, pbDir)
	writeCompose(t, pbDir, pbCompose)
	before, err := os.ReadFile(filepath.Join(pbDir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	out, code = runScript(t, path, []string{"STUB_MOUNT=" + pbMount}, "--clerk-file", clerk, "--compose-file", filepath.Join(pbDir, "compose.yml"))
	if code == 0 || !strings.Contains(out, "not the fields-postgres-v2 map") {
		t.Fatalf("pocketbase compose should refuse, code %d\n%s", code, out)
	}
	after, err := os.ReadFile(filepath.Join(pbDir, "compose.yml"))
	if err != nil || string(after) != string(before) {
		t.Fatalf("live pocketbase compose changed: %q %v", after, err)
	}
	got, err := os.ReadFile(filepath.Join(pbMount, "data.db"))
	if err != nil || string(got) != "pocketbase" {
		t.Fatalf("pocketbase data changed: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(pbDir, "secrets", "current")); !os.IsNotExist(err) {
		t.Fatal("pocketbase compose produced a ready generation")
	}
}

func TestStatusLineAndMissing(t *testing.T) {
	_, appDir, stateFile, lock, _ := scopedPaths(t)
	writeState(t, stateFile, appDir)
	writeCompose(t, appDir, placeholderCompose)
	status := renderScoped(t, fieldsScopedStatusBody, appDir, stateFile, lock)
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte(status), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, path, nil)
	if code != 0 || out != "wire=v2 profile=fields-postgres-v2 source=host-local state=missing generation=none reason=no-current\n" {
		t.Fatalf("missing status code %d %q", code, out)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	clerk := filepath.Join(t.TempDir(), "clerk")
	writeClerk(t, clerk, "https://app.example")
	prov := renderScoped(t, fieldsScopedEnvBody, appDir, stateFile, lock)
	pp := filepath.Join(t.TempDir(), "provision")
	if err := os.WriteFile(pp, []byte(prov), 0o700); err != nil {
		t.Fatal(err)
	}
	placeholder := filepath.Join(t.TempDir(), "placeholder.yml")
	if err := os.WriteFile(placeholder, []byte(placeholderCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	pout, pcode := runScript(t, pp, nil, "--clerk-file", clerk, "--compose-file", placeholder)
	if pcode == 0 || !strings.Contains(pout, "not the fields-postgres-v2 map") {
		t.Fatalf("placeholder should not provision, code %d\n%s", pcode, pout)
	}
	out, code = runScript(t, path, nil)
	if code != 0 || out != "wire=v2 profile=fields-postgres-v2 source=host-local state=missing generation=none reason=no-current\n" {
		t.Fatalf("placeholder provision claimed ready, code %d %q", code, out)
	}
	candidate := filepath.Join(t.TempDir(), "candidate.yml")
	if err := os.WriteFile(candidate, []byte(pgCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	pout, pcode = runScript(t, pp, nil, "--clerk-file", clerk, "--compose-file", candidate)
	if pcode != 0 {
		t.Fatal(pout)
	}
	id := strings.TrimPrefix(strings.TrimSpace(pout), "generation=")
	out, code = runScript(t, path, nil)
	want := "wire=v2 profile=fields-postgres-v2 source=host-local state=ready generation=" + id + " reason=ok\n"
	if code != 0 || out != want {
		t.Fatalf("ready status code %d\n got %q\nwant %q", code, out, want)
	}
	extra, code := runScript(t, path, nil, "status")
	if code == 0 || extra != "" {
		t.Fatalf("status with args code %d %q", code, extra)
	}
}

func TestProvisionRefusesBadClerkBeforeWrite(t *testing.T) {
	_, appDir, stateFile, lock, _ := scopedPaths(t)
	writeState(t, stateFile, appDir)
	writeCompose(t, appDir, placeholderCompose)
	clerk := filepath.Join(t.TempDir(), "clerk")
	candidate := filepath.Join(t.TempDir(), "candidate.yml")
	if err := os.WriteFile(candidate, []byte(pgCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clerk, []byte("CLERK_ISSUER=https://clerk.example/$x\nCLERK_JWKS_URL=https://clerk.example/jwks\nCLERK_AUTHORIZED_PARTIES=https://app.example\nCLERK_SECRET_KEY="+clerkSecretFixture+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := renderScoped(t, fieldsScopedEnvBody, appDir, stateFile, lock)
	path := filepath.Join(t.TempDir(), "provision")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, path, nil, "--clerk-file", clerk, "--compose-file", candidate)
	if code == 0 || strings.Contains(out, "$x") || strings.Contains(out, clerkSecretFixture) {
		t.Fatal("bad clerk was accepted or printed")
	}
	if _, err := os.Stat(filepath.Join(appDir, "secrets")); !os.IsNotExist(err) {
		t.Fatal("bad clerk wrote secrets")
	}
}

func TestProvisionRefusesClerkKeyShapePresetAndArgv(t *testing.T) {
	_, appDir, stateFile, lock, _ := scopedPaths(t)
	writeState(t, stateFile, appDir)
	candidate := filepath.Join(t.TempDir(), "candidate.yml")
	if err := os.WriteFile(candidate, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := renderScoped(t, fieldsScopedEnvBody, appDir, stateFile, lock)
	path := filepath.Join(t.TempDir(), "provision")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := "sk_live_MustNotBePrinted"
	testKey := "sk_test_MustNotBePrinted"
	valid := "CLERK_ISSUER=https://clerk.example\nCLERK_JWKS_URL=https://clerk.example/jwks\nCLERK_AUTHORIZED_PARTIES=https://app.example\nCLERK_SECRET_KEY=" + clerkSecretFixture + "\n"
	cases := []struct {
		name  string
		body  string
		env   []string
		extra []string
		want  string
	}{
		{name: "wrong key", body: "CLERK_OTHER=nope\nCLERK_JWKS_URL=https://clerk.example/jwks\nCLERK_AUTHORIZED_PARTIES=https://app.example\nCLERK_SECRET_KEY=" + clerkSecretFixture + "\n", want: "not a fixed Clerk key"},
		{name: "missing key", body: "CLERK_ISSUER=https://clerk.example\nCLERK_JWKS_URL=https://clerk.example/jwks\nCLERK_AUTHORIZED_PARTIES=https://app.example\n", want: "exactly four"},
		{name: "duplicate key", body: "CLERK_ISSUER=https://clerk.example\nCLERK_ISSUER=https://other.example\nCLERK_JWKS_URL=https://clerk.example/jwks\nCLERK_AUTHORIZED_PARTIES=https://app.example\n", want: "repeats a key"},
		{name: "sk_test", body: strings.Replace(valid, "CLERK_SECRET_KEY="+clerkSecretFixture, "CLERK_SECRET_KEY="+testKey, 1), want: "not a production key"},
		{name: "preset", body: valid, env: []string{"CLERK_SECRET_KEY=" + secret}, want: "set in the environment"},
		{name: "argv", body: valid, extra: []string{"--clerk-secret", secret}, want: "unexpected argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clerk := filepath.Join(t.TempDir(), "clerk")
			if err := os.WriteFile(clerk, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"--clerk-file", clerk, "--compose-file", candidate}, tc.extra...)
			out, code := runScript(t, path, tc.env, args...)
			if code == 0 || !strings.Contains(out, tc.want) || strings.Contains(out, secret) || strings.Contains(out, testKey) || strings.Contains(out, clerkSecretFixture) {
				t.Fatalf("%s accepted or printed a value", tc.name)
			}
			if _, err := os.Stat(filepath.Join(appDir, "secrets")); !os.IsNotExist(err) {
				t.Fatal("refused clerk wrote secrets")
			}
		})
	}
}

func TestStatusRejectsV1RecordAndTenKeyGeneration(t *testing.T) {
	_, appDir, stateFile, lock, _ := scopedPaths(t)
	id := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(stateFile, []byte("APP_NAME=fieldsofrevik\nAPP_DIR="+appDir+"\nSCOPED_ENV=fields-postgres-v1\nSCOPED_GENERATION="+id+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	status := renderScoped(t, fieldsScopedStatusBody, appDir, stateFile, lock)
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte(status), 0o755); err != nil {
		t.Fatal(err)
	}
	want := "wire=v2 profile=fields-postgres-v2 source=host-local state=invalid generation=none reason=profile-mismatch\n"
	out, code := runScript(t, path, nil)
	if code != 0 || out != want {
		t.Fatalf("v1 record status code %d %q", code, out)
	}

	gen := filepath.Join(appDir, "secrets", "generations", id)
	if err := os.MkdirAll(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(appDir, "secrets"), filepath.Join(appDir, "secrets", "generations"), gen} {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"postgres.env", "migrate.env", "api.env", "godot-api.env"} {
		body := v2EnvFixture(name)
		if name == "api.env" {
			body = strings.Replace(body, "CLERK_SECRET_KEY=sk_live_deployfixture\n", "", 1)
		}
		if err := os.WriteFile(filepath.Join(gen, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("generations/"+id, filepath.Join(appDir, "secrets", "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, []byte("APP_NAME=fieldsofrevik\nAPP_DIR="+appDir+"\nSCOPED_ENV=fields-postgres-v2\nSCOPED_GENERATION="+id+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	out, code = runScript(t, path, nil)
	if code != 0 || out != want || strings.Contains(out, "sk_live_") {
		t.Fatalf("ten-key status code %d %q", code, out)
	}

	sentinel := "STATUS_SENTINEL_MUST_NOT_ECHO"
	if err := os.WriteFile(filepath.Join(gen, "api.env"), []byte("CLERK_SECRET_KEY="+sentinel+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, "provenance"), []byte("profile=fields-postgres-v2\nschema=11\ngeneration="+id+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	out, code = runScript(t, path, nil)
	ready := "wire=v2 profile=fields-postgres-v2 source=host-local state=ready generation=" + id + " reason=ok\n"
	if code != 0 || out != ready || strings.Contains(out, sentinel) {
		t.Fatalf("marker status read or refused env bytes: code %d %q", code, out)
	}
	ownerBin := filepath.Join(t.TempDir(), "ownerbin")
	if err := os.MkdirAll(ownerBin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStub(t, ownerBin, "id", "#!/bin/sh\nif [ \"$1\" = \"-u\" ]; then echo 0; exit 0; fi\nexit 0\n")
	writeStub(t, ownerBin, "stat", "#!/bin/sh\nfmt=\nfile=\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -c) fmt=$2; shift 2 ;;\n    *) file=$1; shift ;;\n  esac\ndone\nif [ \"$fmt\" = \"%u\" ]; then\n  case \"$file\" in\n    */provenance) echo 1000 ;;\n    *) echo 0 ;;\n  esac\n  exit 0\nfi\nif [ \"$fmt\" = \"%a\" ] || [ \"$fmt\" = \"%s\" ]; then\n  /usr/bin/stat -c \"$fmt\" \"$file\"\n  exit 0\nfi\nif [ -d \"$file\" ]; then echo 700; else echo 600; fi\n")
	out, code = runScript(t, path, []string{"PATH=" + ownerBin + ":/usr/bin:/bin"})
	badOwner := "wire=v2 profile=fields-postgres-v2 source=host-local state=invalid generation=none reason=bad-mode\n"
	if code != 0 || out != badOwner || strings.Contains(out, sentinel) {
		t.Fatalf("non-root provenance status code %d %q", code, out)
	}

	if err := os.Remove(filepath.Join(gen, "provenance")); err != nil {
		t.Fatal(err)
	}
	out, code = runScript(t, path, nil)
	if code != 0 || out != want || strings.Contains(out, sentinel) {
		t.Fatal("generation without provenance was reported ready or printed")
	}
	if err := os.WriteFile(filepath.Join(gen, "provenance"), []byte("profile=fields-postgres-v1\nschema=11\ngeneration="+id+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	out, code = runScript(t, path, nil)
	if code != 0 || out != want || strings.Contains(out, sentinel) {
		t.Fatal("wrong provenance profile was reported ready or printed")
	}
	loose := filepath.Join(gen, "provenance")
	if err := os.Chmod(loose, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loose, []byte("profile=fields-postgres-v2\nschema=11\ngeneration="+id+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = runScript(t, path, nil)
	badMode := "wire=v2 profile=fields-postgres-v2 source=host-local state=invalid generation=none reason=bad-mode\n"
	if code != 0 || out != badMode || strings.Contains(out, sentinel) {
		t.Fatalf("loose provenance mode code %d %q", code, out)
	}
	if strings.Contains(fieldsScopedStatusBody, "CLERK_SECRET_KEY") || strings.Contains(fieldsScopedStatusBody, "api.env\"") {
		t.Fatal("status script still opens an env value")
	}
}

func TestProvisionRefusesPermutedEnvFiles(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	_, appDir, stateFile, lock, _ := scopedPaths(t)
	writeState(t, stateFile, appDir)
	swapped := strings.Replace(pgCompose,
		"image: postgres:16\n    env_file: [./secrets/current/postgres.env]",
		"image: postgres:16\n    env_file: [./secrets/current/migrate.env]", 1)
	swapped = strings.Replace(swapped,
		"image: migrate:1\n    env_file: [./secrets/current/migrate.env]",
		"image: migrate:1\n    env_file: [./secrets/current/postgres.env]", 1)
	candidate := filepath.Join(t.TempDir(), "swapped.yml")
	if err := os.WriteFile(candidate, []byte(swapped), 0o644); err != nil {
		t.Fatal(err)
	}
	clerk := filepath.Join(t.TempDir(), "clerk")
	writeClerk(t, clerk, "https://app.example")
	script := renderScoped(t, fieldsScopedEnvBody, appDir, stateFile, lock)
	path := filepath.Join(t.TempDir(), "provision")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, path, nil, "--clerk-file", clerk, "--compose-file", candidate)
	if code == 0 || !strings.Contains(out, "not the fields-postgres-v2 map") {
		t.Fatalf("permuted env files should refuse, code %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(appDir, "secrets", "current")); !os.IsNotExist(err) {
		t.Fatal("permuted map wrote a generation")
	}
}

func TestDeployReadyComparesExpectedGeneration(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRootStubs(t, bin)
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	const start = "komizo_scoped_env_ready() {"
	const end = "# Operator-written host-wide floors"
	i := strings.Index(AlpineScript, start)
	j := strings.Index(AlpineScript, end)
	if i < 0 || j < i {
		t.Fatal("deploy preflight function was not found")
	}
	fn := AlpineScript[i:j]
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
	fnStart := strings.Index(AlpineScript, startFn)
	fnEnd := strings.Index(AlpineScript, "# Operator-written host-wide floors")
	if fnStart < 0 || fnEnd < fnStart || strings.Contains(AlpineScript[fnStart:fnEnd], "CLERK_SECRET_KEY") {
		t.Fatal("deploy preflight still names a secret")
	}
}

func TestShippedDeployArgvContract(t *testing.T) {
	for _, want := range []string{
		"deploy: refusing: scoped generation missing",
		"deploy: refusing: scoped generation malformed",
		"deploy: refusing: unexpected arguments",
		"deploy: scoped-generation=$expected_generation",
		"provision-scoped-env-$APP_NAME --check-compose",
		"deploy: refusing: scoped env is not a fields-postgres-v2 generation",
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
		`rm -f "$DEPLOY_BIN" "$SECRET_BIN" "$TASK_BIN" "$SCOPED_BIN" "$PROVISION_BIN" "$STATUS_BIN"`,
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
