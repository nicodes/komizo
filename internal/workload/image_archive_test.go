package workload

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func imageArchiveFixture(t *testing.T, files [][2]string) []byte {
	t.Helper()
	var body bytes.Buffer
	w := tar.NewWriter(&body)
	for _, file := range files {
		if err := w.WriteHeader(&tar.Header{Name: file[0], Size: int64(len(file[1])), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(file[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func TestDockerArchiveConfigurationContentAndOrdering(t *testing.T) {
	config := `{"rootfs":{"type":"layers","diff_ids":["sha256:layer"]}}`
	want := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(config)))
	for _, name := range []string{"config.json", "blobs/sha256/config"} {
		files := [][2]string{{name, config}, {"manifest.json", `[{"Config":"` + name + `","Layers":[]}]`}}
		for _, reverse := range []bool{false, true} {
			if reverse {
				files[0], files[1] = files[1], files[0]
			}
			got, err := DockerArchiveConfigDigest(bytes.NewReader(imageArchiveFixture(t, files)))
			if err != nil || got != want {
				t.Fatalf("configuration content was not authenticated: %s %v", got, err)
			}
		}
	}
}

func TestDockerArchiveRejectsMissingAmbiguousAndTruncatedContent(t *testing.T) {
	for _, files := range [][][2]string{
		{{"manifest.json", `[{"Config":"missing"}]`}},
		{{"config", `{}`}, {"manifest.json", `[{"Config":"config"},{"Config":"config"}]`}},
		{{"config", `{}`}, {"config", `{}`}, {"manifest.json", `[{"Config":"config"}]`}},
		{{"../config", `{}`}, {"manifest.json", `[{"Config":"../config"}]`}},
		{{"config", `{}`}, {"manifest.json", `[{"Config":"config","Config":"other"}]`}},
	} {
		if _, err := DockerArchiveConfigDigest(bytes.NewReader(imageArchiveFixture(t, files))); err == nil {
			t.Fatal("ambiguous or incomplete local image accepted")
		}
	}
	if _, err := DockerArchiveConfigDigest(bytes.NewReader([]byte("truncated"))); err == nil {
		t.Fatal("truncated image accepted")
	}
}
