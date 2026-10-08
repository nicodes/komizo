package box

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"text/template"
)

func validateRevikPreviewImages(images []string) error {
	components := []string{"gate", "api", "godot-api", "postgres"}
	if len(images) != len(components) {
		return fmt.Errorf("Revik preview requires gate, api, godot-api and postgres images in that order")
	}
	sha := ""
	for i, component := range components {
		prefix := "ghcr.io/aviorstudio/fieldsofrevik-preview-" + component + ":"
		tag := strings.TrimPrefix(images[i], prefix)
		if !strings.HasPrefix(images[i], prefix) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(tag) || (sha != "" && tag != sha) {
			return fmt.Errorf("Revik preview requires four matching immutable revision tags")
		}
		sha = tag
	}
	return nil
}

func validateRevikPreviewAuth(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Revik preview needs stack.env with development Clerk configuration")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(body) > 4096 {
		return fmt.Errorf("Revik preview needs a bounded stack.env with development Clerk configuration")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		_, duplicate := values[key]
		if !ok || (key != "CLERK_SECRET_KEY" && key != "CLERK_ISSUER" && key != "CLERK_JWKS_URL") || duplicate {
			return fmt.Errorf("Revik preview Clerk configuration contains an unsupported or duplicate field")
		}
		values[key] = value
	}
	key := values["CLERK_SECRET_KEY"]
	issuer := values["CLERK_ISSUER"]
	if !regexp.MustCompile(`^sk_test_[A-Za-z0-9_-]{8,193}$`).MatchString(key) ||
		!regexp.MustCompile(`^https://[a-z0-9-]+\.clerk\.accounts\.dev$`).MatchString(issuer) ||
		values["CLERK_JWKS_URL"] != issuer+"/.well-known/jwks.json" {
		return fmt.Errorf("Revik preview requires matching development Clerk coordinates and an sk_test_ key")
	}
	return nil
}

func revikPreviewCredential(seed, role string) string {
	h := hmac.New(sha256.New, []byte(seed))
	h.Write([]byte("komizo-revik-preview:" + role))
	return hex.EncodeToString(h.Sum(nil))
}

func revikPreviewCompose(r PreviewRecord, k PreviewKnob, network string) string {
	data := struct {
		PreviewRecord
		PreviewKnob
		Network, Host, APIHost, Admin, Migrator, Runtime, Backup, Bridge string
	}{r, k, network, r.WebHost(k), r.PublicAPIHost(k),
		revikPreviewCredential(r.DBPassword, "admin"), revikPreviewCredential(r.DBPassword, "migrator"),
		revikPreviewCredential(r.DBPassword, "runtime"), revikPreviewCredential(r.DBPassword, "backup"),
		revikPreviewCredential(r.DBPassword, "bridge")}
	var b strings.Builder
	_ = revikPreviewTemplate.Execute(&b, data) // Static template, string fields only.
	return b.String()
}

var revikPreviewTemplate = template.Must(template.New("revik-preview").Parse(`
# Written by komizo preview. Every volume and private network belongs to this PR.
x-runtime: &runtime
  restart: unless-stopped
  read_only: true
  cap_drop: [ALL]
  security_opt: [no-new-privileges:true]
  pids_limit: 128
  mem_limit: {{.MemLimit}}
  cpus: {{.CPULimit}}
  tmpfs: ["/tmp:rw,noexec,nosuid,size=64m,mode=1777"]
services:
  postgres:
    <<: *runtime
    image: {{index .Images 3}}
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]
    tmpfs: ["/tmp:rw,nosuid,size=32m,mode=1777", "/var/run/postgresql:rw,nosuid,size=16m,mode=1777"]
    environment:
      POSTGRES_USER: postgres
      POSTGRES_DB: postgres
      PGDATA: /var/lib/postgresql/data
      POSTGRES_PASSWORD: {{.Admin}}
      REVIK_MIGRATOR_PASSWORD: {{.Migrator}}
      REVIK_APP_PASSWORD: {{.Runtime}}
      REVIK_BACKUP_PASSWORD: {{.Backup}}
    volumes: [pg_data:/var/lib/postgresql/data]
    networks: [db]
    healthcheck:
      test: [CMD-SHELL, 'test "$$(cat /proc/1/comm)" = postgres && pg_isready -d revik -U postgres']
      interval: 5s
      timeout: 3s
      retries: 24
      start_period: 20s
  migrate:
    <<: *runtime
    image: {{index .Images 1}}
    restart: "no"
    entrypoint: [/app/server, migrate]
    environment:
      DATABASE_MIGRATION_URL: postgres://revik_migrator:{{.Migrator}}@postgres:5432/revik?sslmode=disable
    networks: [db]
    depends_on:
      postgres: {condition: service_healthy}
  api:
    <<: *runtime
    image: {{index .Images 1}}
    env_file: [stack.env]
    environment:
      DATABASE_URL: postgres://revik_app:{{.Runtime}}@postgres:5432/revik?sslmode=disable
      REVIK_ENV: preview
      HTTP_PORT: "3111"
      WS_PORT: "3112"
      WS_SECRET: {{.Bridge}}
      ALLOWED_ORIGINS: https://{{.Host}}
      CLERK_AUTHORIZED_PARTIES: https://{{.Host}}
    networks: [db, app]
    depends_on:
      migrate: {condition: service_completed_successfully}
    healthcheck:
      test: [CMD, wget, -q, --spider, 'http://127.0.0.1:3111/health']
      interval: 5s
      timeout: 3s
      retries: 24
  godot-api:
    <<: *runtime
    image: {{index .Images 2}}
    environment:
      PORT: "3110"
      GOLANG_WS_URL: ws://api:3112
      WS_SECRET: {{.Bridge}}
      REDIS_HOST: redis
      REDIS_PORT: "3113"
      TEST_MODE: "false"
      XDG_DATA_HOME: /tmp/godot
      XDG_CONFIG_HOME: /tmp/godot-config
    networks: [app]
    depends_on:
      api: {condition: service_healthy}
      redis: {condition: service_healthy}
  redis:
    <<: *runtime
    image: redis:7-alpine@sha256:520775a41a63e77e06c73e35d2fd9cc15921a609516818796b4ecbb813078bc7
    user: "999:999"
    volumes: [redis_data:/data]
    command: [redis-server, --port, "3113", --save, "", --appendonly, "yes", --appendfsync, everysec, --maxmemory, 32mb, --maxmemory-policy, noeviction]
    networks: [app]
    healthcheck:
      test: [CMD, redis-cli, -p, "3113", ping]
      interval: 5s
      timeout: 3s
      retries: 12
  gate:
    <<: *runtime
    image: {{index .Images 0}}
    container_name: {{.Project}}-gate
    environment:
      PREVIEW: "1"
      PR: "{{.PR}}"
      BASE_URL: https://{{.Host}}
      PREVIEW_HOST: {{.Host}}
      PREVIEW_API_HOST: {{.APIHost}}
    ports: ["127.0.0.1:{{.GatePort}}:80"]
    networks: [app, shared]
    depends_on:
      api: {condition: service_healthy}
      godot-api: {condition: service_started}
networks:
  db: {internal: true}
  app: {}
  shared: {external: true, name: {{.Network}}}
volumes:
  pg_data: {}
  redis_data: {}
`))
