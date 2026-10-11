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

func TestGodotArchiveHasIndependentStreamingPackEnvelope(t *testing.T) {
	for _, profile := range []string{"spa-v1", "godot-v1"} {
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
		sum, err := StaticTreeForProfile(r, dir, profile)
		_ = r.Close()
		<-done
		if profile == "spa-v1" {
			if err == nil {
				t.Fatal("Godot bounds widened the SPA profile")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			actual, err := StaticTreeChecksumForProfile(dir, profile)
			if err != nil || actual != sum {
				t.Fatal("Godot extraction/checksum disagree", err)
			}
		}
	}
	archive := staticArchive(t, []*tar.Header{{Name: "index.html", Typeflag: tar.TypeReg}, {Name: "oversize.pck", Typeflag: tar.TypeReg, Size: GodotStaticMaxFileBytes + 1}})
	if _, err := StaticTreeForProfile(bytes.NewReader(archive), filepath.Join(t.TempDir(), "public"), "godot-v1"); err == nil {
		t.Fatal("unbounded Godot pack accepted")
	}
}

func TestGodotProfileKeepsIsolationCacheAndParentIdentity(t *testing.T) {
	rev := strings.Repeat("a", 40)
	parent := "example.invalid {\n\theader >X-Komizo-Revision \"" + rev + "\"\n\treverse_proxy example-gate:80 {\n\t\theader_up X-Forwarded-For {remote_host}\n\t}\n}\n"
	body, err := StaticRouteForProfile([]byte(parent), "example", rev, []string{"example.invalid"}, "godot-v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Content-Security-Policy", "precompressed br gzip", "no-cache, no-store, must-revalidate", "public, max-age=31536000, immutable", "application/octet-stream", "X-Komizo-Revision", "/srv/public/example/" + rev} {
		if !strings.Contains(string(body), required) {
			t.Fatal("lost serving contract", required)
		}
	}
	if strings.Contains(string(body), "try_files") {
		t.Fatal("Godot missing files became successful SPA responses")
	}
	if _, err := StaticRouteForProfile([]byte(parent), "example", rev, []string{"example.invalid"}, "unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}
