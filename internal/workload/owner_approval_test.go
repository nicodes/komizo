package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOwnerApprovalRequiresProtectedOptInAndExactScope(t *testing.T) {
	p, err := NewPolicy("example", "/srv/example", "registry.example/example-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	version := strings.Repeat("a", 40)
	m := ReleaseManifest{Version: 1, Revision: version, Images: map[string]string{
		p.ImagePrefix + "api:" + version:    "sha256:" + strings.Repeat("1", 64),
		p.ImagePrefix + "config:" + version: "sha256:" + strings.Repeat("2", 64)}}
	raw, _ := json.Marshal(m)
	if _, err := ApproveOwnerRelease(raw, p, version, time.Now()); err == nil {
		t.Fatal("base registration approved artifacts")
	}
	p.OwnerApproval = true
	accepted, err := ApproveOwnerRelease(raw, p, version, time.Now())
	if err != nil || accepted.Authority != "owner-ssh" || accepted.Manifest.RunID != "" || accepted.Manifest.Repository != "" {
		t.Fatal(accepted, err)
	}
	if err := accepted.Check(p, version); err != nil {
		t.Fatal(err)
	}
	foreign := p
	foreign.OwnerApproval = false
	foreign.SourceRepository = "example/repo"
	foreign.RepositoryID = "123"
	if _, err := ApproveOwnerRelease(raw, foreign, version, time.Now()); err == nil {
		t.Fatal("owner input bypassed GitHub authority")
	}
	if err := accepted.Check(foreign, version); err == nil {
		t.Fatal("approval crossed host trust mode")
	}
	for _, change := range []func(*Policy){
		func(q *Policy) { q.SourceRepository = "example/repo"; q.RepositoryID = "123" },
		func(q *Policy) { q.RequireDeliveryAuthorization = true },
	} {
		q := p
		change(&q)
		if q.Check() == nil {
			t.Fatal("mixed authority accepted")
		}
	}
	for _, change := range []func(*ReleaseManifest){
		func(q *ReleaseManifest) { q.Revision = strings.Repeat("b", 40) },
		func(q *ReleaseManifest) { q.Repository = "foreign/repo" },
		func(q *ReleaseManifest) { q.TestedCommit = version },
		func(q *ReleaseManifest) { q.RunID = "123" },
		func(q *ReleaseManifest) {
			q.Images = map[string]string{"registry.example/foreign-api:" + version: "sha256:" + strings.Repeat("1", 64), p.ImagePrefix + "config:" + version: "sha256:" + strings.Repeat("2", 64)}
		},
		func(q *ReleaseManifest) {
			q.Images = map[string]string{p.ImagePrefix + "api:" + version: "latest", p.ImagePrefix + "config:" + version: "sha256:" + strings.Repeat("2", 64)}
		},
	} {
		q := m
		change(&q)
		body, _ := json.Marshal(q)
		if _, err := ApproveOwnerRelease(body, p, version, time.Now()); err == nil {
			t.Fatal("foreign or unverified approval accepted", string(body))
		}
	}
	duplicate := bytes.Replace(raw, []byte("\"version\":1"), []byte("\"version\":1,\"version\":1"), 1)
	for _, body := range [][]byte{duplicate, append(append([]byte{}, raw...), raw...)} {
		if _, err := ApproveOwnerRelease(body, p, version, time.Now()); err == nil {
			t.Fatal("ambiguous approval accepted")
		}
	}
}

func TestOwnerApprovedImagesStillRequireExactConfigurationBytes(t *testing.T) {
	p, err := NewPolicy("example", "/srv/example", "registry.example/example-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	p.OwnerApproval = true
	version := strings.Repeat("a", 40)
	m := ReleaseManifest{Version: 1, Revision: version, Images: map[string]string{p.ImagePrefix + "api:" + version: "sha256:" + strings.Repeat("1", 64), p.ImagePrefix + "config:" + version: "sha256:" + strings.Repeat("2", 64)}}
	raw, _ := json.Marshal(m)
	accepted, err := ApproveOwnerRelease(raw, p, version, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	run := func(_ context.Context, args ...string) (string, error) {
		if args[0] == "pull" {
			return "", nil
		}
		ref := args[2]
		id := m.Images[ref]
		if changed && strings.Contains(ref, "-api:") {
			id = "sha256:" + strings.Repeat("f", 64)
		}
		repository := strings.TrimSuffix(ref, ":"+version)
		body, _ := json.Marshal([]map[string]any{{"Id": id, "RepoDigests": []string{repository + "@sha256:" + strings.Repeat("9", 64)}}})
		return string(body), nil
	}
	compose, _ := json.Marshal(map[string]any{"services": map[string]any{"api": map[string]string{"image": p.ImagePrefix + "api:" + version}}})
	if _, err := BindRelease(context.Background(), run, p, accepted, version, p.ImagePrefix+"config:"+version, compose); err != nil {
		t.Fatal(err)
	}
	changed = true
	if _, err := BindRelease(context.Background(), run, p, accepted, version, p.ImagePrefix+"config:"+version, compose); err == nil {
		t.Fatal("owner approval accepted substituted registry bytes")
	}
}
