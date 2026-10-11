package workload

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func staticArchive(t *testing.T, headers []*tar.Header) []byte {
	t.Helper()
	var body bytes.Buffer
	w := tar.NewWriter(&body)
	for _, header := range headers {
		if err := w.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 && header.Size < 1024 {
			_, _ = w.Write(bytes.Repeat([]byte("x"), int(header.Size)))
		}
	}
	_ = w.Close()
	return body.Bytes()
}

func TestStaticArchiveIsBoundedImmutableAndPreservesFileTime(t *testing.T) {
	stamp := time.Unix(1700000000, 0)
	archive := staticArchive(t, []*tar.Header{{Name: "./index.html", Typeflag: tar.TypeReg, Size: 10, Mode: 0777, ModTime: stamp},
		{Name: "./_expo/app.js", Typeflag: tar.TypeReg, Size: 12, Mode: 0777, ModTime: stamp}, {Name: "./_expo/.routes.json", Typeflag: tar.TypeReg, Size: 2}})
	directory := filepath.Join(t.TempDir(), "public")
	identity, err := StaticTree(bytes.NewReader(archive), directory)
	if err != nil || len(identity) != 64 {
		t.Fatal(identity, err)
	}
	info, err := os.Stat(filepath.Join(directory, "index.html"))
	if err != nil || info.Mode().Perm() != 0444 || !info.ModTime().Equal(stamp) {
		t.Fatal("archive-controlled permissions or altered cache validator", info, err)
	}
	actual, err := StaticTreeChecksum(directory)
	if err != nil || actual != identity {
		t.Fatal("extraction/checksum disagree", actual, identity, err)
	}
	if err := os.Chmod(filepath.Join(directory, "index.html"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := StaticTreeChecksum(directory); err == nil {
		t.Fatal("writable cache accepted")
	}
}

func TestStaticArchiveRefusesEscapeLinksDuplicatesSecretsAndOversize(t *testing.T) {
	for _, header := range []*tar.Header{
		{Name: "../outside", Typeflag: tar.TypeReg}, {Name: "/outside", Typeflag: tar.TypeReg},
		{Name: "a/../outside", Typeflag: tar.TypeReg}, {Name: ".env", Typeflag: tar.TypeReg},
		{Name: "a/.key", Typeflag: tar.TypeReg}, {Name: "a\\b", Typeflag: tar.TypeReg},
		{Name: "linked", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "linked", Typeflag: tar.TypeLink, Linkname: "index.html"},
		{Name: "device", Typeflag: tar.TypeChar}, {Name: "large", Typeflag: tar.TypeReg, Size: StaticMaxFileBytes + 1},
		{Name: "index.html", Typeflag: tar.TypeReg}, {Name: "INDEX.HTML", Typeflag: tar.TypeReg},
	} {
		t.Run(header.Name+string(header.Typeflag), func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "public")
			body := staticArchive(t, []*tar.Header{{Name: "index.html", Typeflag: tar.TypeReg}, header})
			if _, err := StaticTree(bytes.NewReader(body), directory); err == nil {
				t.Fatal("unsafe public archive accepted")
			}
			if _, err := os.Lstat(directory); !os.IsNotExist(err) {
				t.Fatal("failed extraction left an adoptable public directory", err)
			}
		})
	}
	if _, err := StaticTree(bytes.NewReader(nil), filepath.Join(t.TempDir(), "public")); err == nil {
		t.Fatal("missing entry point accepted")
	}
}

func TestStaticProfilePreservesParentRouteAndRefusesAdditionalServices(t *testing.T) {
	parent := "example.invalid {\n\theader >X-Komizo-Revision \"" + strings.Repeat("a", 40) + "\"\n\theader Strict-Transport-Security max-age=31536000\n" +
		"\treverse_proxy example-gate:80 {\n\t\theader_up X-Forwarded-For {remote_host}\n\t}\n}\n"
	route, err := StaticRoute([]byte(parent), "example", strings.Repeat("a", 40), []string{"example.invalid"})
	if err != nil || !strings.Contains(string(route), "try_files {path} {path}.html {path}/index.html /index.html") ||
		!strings.Contains(string(route), "header >X-Komizo-Revision") || !strings.Contains(string(route), "Strict-Transport-Security max-age=31536000") || strings.Contains(string(route), "reverse_proxy") {
		t.Fatal(string(route), err)
	}
	if _, err := StaticRoute([]byte(strings.ReplaceAll(parent, "example-gate", "other-gate")), "example", strings.Repeat("a", 40), []string{"example.invalid"}); err == nil {
		t.Fatal("foreign upstream transformed")
	}
	if _, err := StaticRoute([]byte(parent), "example", strings.Repeat("a", 40), []string{"other.invalid"}); err == nil {
		t.Fatal("unreviewed hostname transformed")
	}
	for _, services := range []map[string]any{
		{"example-gate": map[string]string{"image": "ghcr.io/example/gate:mutable"}},
		{"other-gate": map[string]string{"image": "ghcr.io/example/gate@sha256:" + strings.Repeat("a", 64)}},
		{"example-gate": map[string]string{"image": "ghcr.io/example/gate@sha256:" + strings.Repeat("a", 64)}, "postgres": map[string]string{}},
	} {
		body, _ := json.Marshal(map[string]any{"services": services})
		if _, err := StaticGate(body, "example"); err == nil {
			t.Fatal("non-gate-only immutable workload accepted")
		}
	}
}
