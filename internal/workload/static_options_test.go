package workload

import (
	"archive/tar"
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestStaticLimitsKeepIndependentStreamingEnvelopes(t *testing.T) {
	for _, name := range []string{"html_fallback", "cache_rules", "root_assets", "immutable_assets"} {
		limits := staticFixture(t, name).Limits
		r, w := io.Pipe()
		done := make(chan error, 1)
		go func() {
			archive := tar.NewWriter(w)
			err := archive.WriteHeader(&tar.Header{Name: "index.html", Size: 1, Mode: 0444})
			if err == nil {
				_, err = archive.Write([]byte("x"))
			}
			if err == nil {
				err = archive.WriteHeader(&tar.Header{Name: "releases/" + strings.Repeat("a", 64) + "/game.pck", Size: 17 << 20, Mode: 0444})
			}
			if err == nil {
				_, err = io.CopyN(archive, zeroReader{}, 17<<20)
			}
			if err == nil {
				err = archive.Close()
			}
			_ = w.CloseWithError(err)
			done <- err
		}()
		dir := filepath.Join(t.TempDir(), "public")
		sum, err := StaticTree(r, dir, limits)
		_ = r.Close()
		<-done
		if name == "html_fallback" {
			if err == nil {
				t.Fatal("explicit large bounds widened the conservative default")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			actual, err := StaticTreeChecksum(dir, limits)
			if err != nil || actual != sum {
				t.Fatal("static extraction/checksum disagree", err)
			}
		}
	}
	archive := staticArchive(t, []*tar.Header{{Name: "index.html", Typeflag: tar.TypeReg}, {Name: "oversize.pck", Typeflag: tar.TypeReg, Size: StaticFileBytesCeiling + 1}})
	if _, err := StaticTree(bytes.NewReader(archive), filepath.Join(t.TempDir(), "public"), staticFixture(t, "cache_rules").Limits); err == nil {
		t.Fatal("unbounded static file accepted")
	}
}

func TestStaticOptionsKeepIsolationCacheAndParentIdentity(t *testing.T) {
	rev := strings.Repeat("a", 40)
	parent := "example.invalid {\n\theader >X-Komizo-Revision \"" + rev + "\"\n\treverse_proxy example-gate:80 {\n\t\theader_up X-Forwarded-For {remote_host}\n\t}\n}\n"
	body, err := StaticRoute([]byte(parent), "example", rev, []string{"example.invalid"}, staticFixture(t, "cache_rules").Serving)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Content-Security-Policy", "precompressed br gzip", "no-cache, no-store, must-revalidate", "public, max-age=31536000, immutable", "application/octet-stream", "X-Komizo-Revision", "/srv/public/example/" + rev} {
		if !strings.Contains(string(body), required) {
			t.Fatal("lost serving contract", required)
		}
	}
	if strings.Contains(string(body), "try_files") {
		t.Fatal("missing files became successful fallback responses")
	}
	if _, err := StaticRoute([]byte(parent), "example", rev, []string{"example.invalid"}, StaticServingOptions{Encode: []string{"unknown"}}); err == nil {
		t.Fatal("unknown encoding accepted")
	}
}

func TestStaticOptionsPreserveExistingRootAssets(t *testing.T) {
	revision := strings.Repeat("a", 40)
	parent := "example.invalid {\n\theader >X-Komizo-Revision \"" + revision + "\"\n\treverse_proxy example-gate:80 {\n\t\theader_up X-Forwarded-For {remote_host}\n\t}\n}\n"
	legacy, err := StaticRoute([]byte(parent), "example", revision, []string{"example.invalid"}, staticFixture(t, "root_assets").Serving)
	if err != nil {
		t.Fatal(err)
	}
	immutable, err := StaticRoute([]byte(parent), "example", revision, []string{"example.invalid"}, staticFixture(t, "cache_rules").Serving)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), "respond @example_denied 404") || !strings.Contains(string(immutable), "respond @example_denied 404") {
		t.Fatal("layout changed existing asset refusal behavior")
	}
	for _, required := range []string{"Cross-Origin-Embedder-Policy", "precompressed br gzip", "no-cache, must-revalidate", "public, max-age=31536000, immutable"} {
		if !strings.Contains(string(legacy), required) {
			t.Fatal("legacy layout lost serving contract", required)
		}
	}
}

func TestStaticImmutableRulesPreserveMissingPathsAndCompression(t *testing.T) {
	body := staticServingRoute("example", strings.Repeat("a", 40), staticFixture(t, "immutable_assets").Serving)
	for _, required := range []string{"not path \"/releases/*\"", "Cache-Control \"no-cache, no-store, must-revalidate\"", "precompressed gzip", "respond @example_denied 404", "Cross-Origin-Embedder-Policy"} {
		if !strings.Contains(body, required) {
			t.Fatal("immutable layout lost contract", required)
		}
	}
	if strings.Contains(body, "encode gzip") || strings.Contains(body, "precompressed br") || strings.Contains(body, "try_files") {
		t.Fatal("immutable layout changed compression or missing-file behavior")
	}
}
