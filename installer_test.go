//go:build !windows

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCurlInstaller(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	script := filepath.Join(filepath.Dir(file), "install.sh")
	for _, scenario := range []string{"valid", "checksum", "symlink", "duplicate", "missing", "attestation", "auth"} {
		t.Run(scenario, func(t *testing.T) {

			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			fixture := filepath.Join(root, "fixture")
			fake := filepath.Join(root, "commands")
			for _, dir := range []string{bin, fixture, fake} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path string, body []byte, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, body, mode); err != nil {
					t.Fatal(err)
				}
			}
			const tool = "komizo"
			old := []byte("previous executable\n")
			payload := []byte("#!/bin/sh\nprintf 'installed fixture\\n'\n")
			write(filepath.Join(bin, tool), old, 0700)
			var archive bytes.Buffer
			gz := gzip.NewWriter(&archive)
			tw := tar.NewWriter(gz)
			count := 1
			if scenario == "duplicate" {
				count = 2
			}
			for i := 0; i < count; i++ {
				header := &tar.Header{Name: tool, Mode: 0755, Uid: 1001, Gid: 1001, Size: int64(len(payload)), Typeflag: tar.TypeReg}
				if scenario == "symlink" {
					header.Typeflag, header.Linkname, header.Size = tar.TypeSymlink, "/outside", 0
				}
				if scenario == "missing" {
					header.Name = "another-file"
				}
				if err := tw.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if header.Size > 0 {
					if _, err := tw.Write(payload); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(fixture, "archive"), archive.Bytes(), 0600)
			digest := fmt.Sprintf("%x", sha256.Sum256(archive.Bytes()))
			if scenario == "checksum" {
				digest = strings.Repeat("0", 64)
			}
			write(filepath.Join(fixture, "checksums"), []byte(digest+"  "+tool+"_Linux_x86_64.tar.gz\n"), 0600)
			write(filepath.Join(fake, "uname"), []byte("#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo x86_64;; *) exit 1;; esac\n"), 0700)
			write(filepath.Join(fake, "curl"), []byte(`#!/bin/sh
set -eu
printf called >> "$INSTALL_FIXTURE/downloads"
output=
url=
while [ "$#" -gt 0 ]; do
 case "$1" in
  --output) output=$2; shift 2 ;;
  --write-out|--retry|--connect-timeout|--max-time|--proto|--proto-redir) shift 2 ;;
  https://*) url=$1; shift ;;
  *) shift ;;
 esac
done
case "$url" in
 https://github.com/nicodes/komizo/releases/latest) printf 'https://github.com/nicodes/komizo/releases/tag/v1.2.3' ;;
 https://github.com/nicodes/komizo/releases/download/v1.2.3/checksums.txt) cp "$INSTALL_FIXTURE/checksums" "$output" ;;
 https://github.com/nicodes/komizo/releases/download/v1.2.3/komizo_Linux_x86_64.tar.gz) cp "$INSTALL_FIXTURE/archive" "$output" ;;
 *) echo "unexpected download: $url" >&2; exit 1 ;;
esac
`), 0700)
			write(filepath.Join(fake, "gh"), []byte("#!/bin/sh\ncase \"$1 $2\" in \"auth status\") [ \"${INSTALL_AUTH_FAIL:-0}\" != 1 ];; \"attestation verify\") [ \"${INSTALL_ATTEST_FAIL:-0}\" != 1 ];; *) exit 2;; esac\n"), 0700)
			cmd := exec.Command("sh", script, "--install-dir", bin)
			cmd.Env = append(os.Environ(), "PATH="+fake+string(os.PathListSeparator)+os.Getenv("PATH"), "INSTALL_FIXTURE="+fixture)
			if scenario == "attestation" {
				cmd.Env = append(cmd.Env, "INSTALL_ATTEST_FAIL=1")
			}
			if scenario == "auth" {
				cmd.Env = append(cmd.Env, "INSTALL_AUTH_FAIL=1")
			}
			output, err := cmd.CombinedOutput()
			if scenario == "auth" {
				if _, e := os.Stat(filepath.Join(fixture, "downloads")); !os.IsNotExist(e) {
					t.Fatal("download started before authentication preflight")
				}
				if !strings.Contains(string(output), "gh auth login") {
					t.Fatal("missing authentication instruction")
				}
			}
			if scenario == "valid" && err != nil {
				t.Fatalf("install: %v\n%s", err, output)
			}
			if scenario != "valid" && err == nil {
				t.Fatalf("invalid release accepted: %s", output)
			}
			got, err := os.ReadFile(filepath.Join(bin, tool))
			if err != nil {
				t.Fatal(err)
			}
			want := old
			if scenario == "valid" {
				want = payload
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("unexpected executable after %s: %q", scenario, got)
			}
		})
	}
}
