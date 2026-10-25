package project

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const miseVersion = "2026.9.12"

var miseChecksums = map[string]string{
	"linux-amd64":  "e79ae57945034903aee8aa2ea66b4c7ca9cd4f4edd5a8a78a589cbae6d0f428a",
	"linux-arm64":  "f344c6961190ed2f68e595ed7cb4f03c36c17812bd608886bec799a3082180ff",
	"darwin-amd64": "fa1e35456f1e27a4555a1ccec82d5367d7037f3b4f46d48b83c4a3bceb4d78f2",
	"darwin-arm64": "f20d7cc555a5b0ee7b8a504acbc2583be1b0848d64115cfbe84119ceb705025b",
}

func ensureMise(ctx context.Context) (string, error) {
	want, supported := miseChecksums[runtime.GOOS+"-"+runtime.GOARCH]
	if !supported {
		return "", errors.New("project recipes support Linux and macOS on amd64/arm64")
	}
	valid := func(path string) bool {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		data, err := os.ReadFile(path)
		return err == nil && digest(data) == want
	}
	if path, err := exec.LookPath("mise"); err == nil && valid(path) {
		return path, nil
	}
	cache, err := cacheDirectory()
	if err != nil {
		return "", err
	}
	base := filepath.Join(cache, "toolchain", miseVersion+"-"+runtime.GOOS+"-"+runtime.GOARCH)
	if err = os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(base, "mise")
	if valid(path) {
		return path, nil
	}
	osName, arch := runtime.GOOS, runtime.GOARCH
	if osName == "darwin" {
		osName = "macos"
	}
	if arch == "amd64" {
		arch = "x64"
	}
	url := "https://github.com/jdx/mise/releases/download/v" + miseVersion + "/mise-v" + miseVersion + "-" + osName + "-" + arch
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	response, err := (&http.Client{Timeout: 2 * time.Minute}).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("toolchain bootstrap returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	if err != nil || len(data) > 64<<20 || digest(data) != want {
		return "", errors.New("toolchain bootstrap checksum differs")
	}
	if err = atomicFile(path, data, 0o700); err != nil {
		return "", err
	}
	return path, nil
}
