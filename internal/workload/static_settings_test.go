package workload

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStaticServingRejectsConfigurationInjectionAndIdentityOverrides(t *testing.T) {
	for _, settings := range []StaticServingOptions{
		{Headers: map[string]string{"X-Komizo-Revision": "forged"}},
		{Headers: map[string]string{"x-komizo-revision": "forged"}},
		{Headers: map[string]string{"Content-Length": "0"}},
		{Headers: map[string]string{"X-Value": "one\nrespond 200"}},
		{Headers: map[string]string{"X-Value": "{$PRIVATE_ENV}"}},
		{Headers: map[string]string{"X-Value": "one", "x-value": "two"}},
		{Fallbacks: []string{"/../../private"}},
		{Fallbacks: []string{"{env.PRIVATE_ENV}"}},
		{DenyPaths: []string{"/safe\nrespond 200"}},
		{HeaderRules: []StaticHeaderRule{{PathRegexp: "{$PRIVATE_ENV}", Headers: map[string]string{"X-Value": "fixed"}}}},
		{HeaderRules: []StaticHeaderRule{{PathRegexp: "[", Headers: map[string]string{"X-Value": "fixed"}}}},
		{HeaderRules: []StaticHeaderRule{{Paths: []string{"/*"}, Methods: []string{"TRACE"}, Headers: map[string]string{"X-Value": "fixed"}}}},
		{Encode: []string{"br"}},
		{Precompressed: []string{"gzip", "gzip"}},
	} {
		if err := settings.Check(); err == nil {
			t.Fatalf("unsafe serving settings accepted: %+v", settings)
		}
	}
	settings := staticFixture(t, "cache_rules").Serving
	if err := settings.Check(); err != nil {
		t.Fatal("literal RE2 repetition refused", err)
	}
}

func TestStaticArchiveLimitsRemainFiniteAndIndependentlySelected(t *testing.T) {
	for _, limits := range []StaticLimits{
		{MaxBytes: -1}, {MaxFileBytes: -1}, {MaxBytes: StaticBytesCeiling + 1},
		{MaxFileBytes: StaticFileBytesCeiling + 1}, {MaxBytes: 1, MaxFileBytes: 2},
	} {
		if _, _, err := StaticBounds(limits); err == nil {
			t.Fatal("unsafe extraction bounds accepted", limits)
		}
	}
	total, file, err := StaticBounds(StaticLimits{})
	if err != nil || total != StaticMaxBytes || file != StaticMaxFileBytes {
		t.Fatal("conservative defaults changed")
	}
}

func TestStaticServingDenialsPrecedeFallbackRewrites(t *testing.T) {
	settings := staticFixture(t, "html_fallback").Serving
	settings.DenyPaths = []string{"/private/*"}
	body := staticServingRoute("example", strings.Repeat("a", 40), settings)
	if strings.Index(body, "respond @example_denied 404") > strings.Index(body, "try_files") {
		t.Fatal("fallback can bypass an explicit denial")
	}
}

func TestProtectedStaticPolicyRejectsFormerProfilesAndDuplicateFields(t *testing.T) {
	p := Policy{Version: 1, App: "example", AppDir: "/srv/example", ImagePrefix: "registry.invalid/example-", SharedNetwork: "edge",
		SourceRepository: "example/repo", RepositoryID: "123", Readiness: &ReadinessPolicy{Probes: []ReadinessProbe{{URL: "https://example.invalid/"}}}}
	fixture := staticFixture(t, "html_fallback")
	fixture.GateConfigSHA = strings.Repeat("a", 64)
	fixture.Proxy = "proxy"
	fixture.Hostnames = []string{"example.invalid"}
	p.Static = &fixture
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicy(bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(body, []byte("\"image_directory\":"), []byte("\"image_directory\":\"/foreign\",\"image_directory\":"), 1)
	if _, err := ReadPolicy(bytes.NewReader(duplicate)); err == nil {
		t.Fatal("ambiguous source directory accepted")
	}
	former := bytes.Replace(body, []byte("\"image_directory\":\"/srv/public/app\""), []byte("\"profile\":\"spa-v1\""), 1)
	if bytes.Equal(former, body) {
		t.Fatal("fixture did not replace the former schema")
	}
	if _, err := ReadPolicy(bytes.NewReader(former)); err == nil {
		t.Fatal("former static profile schema accepted")
	}
}
