package box

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func unrelatedPreviewProfile(t *testing.T) *PreviewProfile {
	t.Helper()
	p := PreviewProfile{Version: 1, Services: []string{"gate", "mail-worker"}, ImagePrefixes: []string{"ghcr.io/another-account/entry:", "ghcr.io/another-account/mailer:"}, CredentialNamespace: "mailroom-preview:", Credentials: []string{"mailer"}, EnvironmentRules: []PreviewEnvironmentRule{{Name: "DEV_ENDPOINT", Pattern: `^https://[a-z]+\.example\.test$`}}, ComposeTemplate: `
x-common: &common
  cgroup_parent: {{.CgroupParent}}
  cpu_shares: 128
  cpus: {{.CPULimit}}
  pids_limit: 64
services:
  {{.Project}}-gate:
    <<: *common
    image: {{index .Images 0}}
    mem_limit: {{index .Limits "gate"}}
    memswap_limit: {{index .Limits "gate"}}
    ports: ["127.0.0.1:{{.GatePort}}:80"]
    networks: [ingress]
  mail-worker:
    <<: *common
    image: {{index .Images 1}}
    mem_limit: {{index .Limits "mail-worker"}}
    memswap_limit: {{index .Limits "mail-worker"}}
    env_file: [stack.env]
    environment:
      MAIL_TOKEN: {{index .Credentials "mailer"}}
    volumes: [messages:/data]
    networks: [private]
networks:
  private: {internal: true}
  ingress: {external: true, name: {{.Network}}}
volumes:
  messages: {}
`}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePreviewProfile(body)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
func TestOperatorPreviewProfileSupportsUnrelatedTopologyAndStablePrivateCredentials(t *testing.T) {
	cfg := previewTestConfig(t)
	p := unrelatedPreviewProfile(t)
	cfg.Knob.profiles = map[string]*PreviewProfile{"mailroom": p}
	cfg.Knob.cgroupParent = "/komizo-previews"
	cfg.Knob.MemLimit = "16m"
	images := []string{p.ImagePrefixes[0] + strings.Repeat("a", 40), p.ImagePrefixes[1] + strings.Repeat("a", 40)}
	dir := previewDir(cfg.Root, PreviewProject("mailroom", 19))
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stack.env"), []byte("DEV_ENDPOINT=https://mail.example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeDocker{previewDBDown: true}
	first, err := PreviewUp(context.Background(), f.run, cfg, "mailroom", 19, images, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PreviewUp(context.Background(), f.run, cfg, "mailroom", 19, images, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	if !first.PrivateProfile || first.DBName != "" || first.MemoryReservedBytes != 32<<20 || first.ProfileSHA256 != p.digest || first.DBPassword != second.DBPassword {
		t.Fatal("profile identity, budget or private seed lost")
	}
	if err := PreviewDown(context.Background(), f.run, cfg, second); err != nil {
		t.Fatal(err)
	}
	for _, args := range f.calls {
		if strings.Contains(strings.Join(args, " "), PreviewDBContainer) {
			t.Fatal("profile touched shared database")
		}
	}
}
func TestPreviewProfileCannotEscapeAdmissionOrReadHostResources(t *testing.T) {
	p := unrelatedPreviewProfile(t)
	k := PreviewKnob{MemLimit: "16m", CPULimit: "0.1", cgroupParent: "/komizo-previews"}
	r := PreviewRecord{App: "mailroom", Project: "mailroom-pr-19", PR: 19, Images: []string{p.ImagePrefixes[0] + strings.Repeat("a", 40), p.ImagePrefixes[1] + strings.Repeat("a", 40)}, GatePort: 20000, DBPassword: strings.Repeat("b", 24)}
	good, err := p.compose(r, k, r.Project+"-ingress")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.validateCompose(good, r, k, r.Project+"-ingress"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(good, "mem_limit: 16m", "mem_limit: 32m", 1),
		strings.Replace(good, "cgroup_parent: /komizo-previews", "cgroup_parent: /komizo-production", 1),
		strings.Replace(good, "messages:/data", "/srv/another-app/secrets:/data", 1),
		strings.Replace(good, "env_file: [stack.env]", "env_file: [/etc/shadow]", 1),
		strings.Replace(good, "messages: {}", "messages: {external: true, name: production}", 1),
		strings.Replace(good, "private: {internal: true}", "private: {driver: host}", 1),
		strings.Replace(good, "networks: [private]", "networks: [ingress]", 1),
		strings.Replace(good, "127.0.0.1:20000:80", "0.0.0.0:80:80", 1),
	} {
		if err := p.validateCompose(bad, r, k, r.Project+"-ingress"); err == nil {
			t.Fatal("unsafe operator profile escaped generic boundary")
		}
	}
}
func TestPreviewNeedsExplicitDomainAndNoCertificateDefault(t *testing.T) {
	k, _ := ParsePreviewKnob("")
	if len(k.Domains()) != 0 {
		t.Fatal("compiled domain authorization")
	}
	if _, err := ResolvePreview(k, "mailroom", 19, false); err == nil {
		t.Fatal("missing domain accepted")
	}
}
