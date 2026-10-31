//go:build !rustapi

package nativeapi

import (
	"fmt"
	"os"
	"path/filepath"
)

// Source-only Go builds can select a separately built native API. Release
// binaries embed the exact native artifact using the rustapi build tag.
func Prepare() (string, func(), error) {
	path := os.Getenv("KOMIZO_API_BINARY")
	if path == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", nil, err
		}
		path = filepath.Join(filepath.Dir(executable), "komizo-api")
	}
	if !filepath.IsAbs(path) {
		return "", nil, fmt.Errorf("KOMIZO_API_BINARY must be absolute")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return "", nil, fmt.Errorf("native Rust API is unavailable; use a release CLI, run mise run build, or set KOMIZO_API_BINARY to the built api executable")
	}
	return path, func() {}, nil
}
