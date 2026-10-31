package agent

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// prepareNativeSource works only in a private copy of the checksum-verified Go
// module. The shared module cache is never changed. The Rust dependency graph
// is fixed by this same version's Cargo.lock, including registry checksums.
func prepareNativeSource(ctx context.Context, source, destination, arch string) error {
	target, compiler := "", ""
	switch arch {
	case "amd64":
		target, compiler = "x86_64-unknown-linux-musl", "x86_64-linux-musl-gcc"
	case "arm64":
		target, compiler = "aarch64-unknown-linux-musl", "aarch64-linux-musl-gcc"
	default:
		return fmt.Errorf("unsupported box architecture %q", arch)
	}
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		return fmt.Errorf("source-built agents require Rust 1.94.0 and a musl C compiler; install the toolchains or use a release archive")
	}
	rustup, err := exec.LookPath("rustup")
	if err != nil {
		return fmt.Errorf("source-built agents require rustup with Rust 1.94.0")
	}
	ccKey := "CC_" + strings.ReplaceAll(target, "-", "_")
	if selected := os.Getenv(ccKey); selected != "" {
		compiler = selected
	} else {
		if runtime.GOOS == "linux" && runtime.GOARCH == arch {
			compiler = "musl-gcc"
		}
		if _, err := exec.LookPath(compiler); err != nil {
			return fmt.Errorf("building the Rust API for %s needs %s or %s; use a release archive to install without compilers", target, compiler, ccKey)
		}
	}
	if err := copyModule(source, destination); err != nil {
		return err
	}
	setup := exec.CommandContext(ctx, rustup, "target", "add", "--toolchain", "1.94.0", target)
	if out, err := setup.CombinedOutput(); err != nil {
		return fmt.Errorf("preparing the Rust target: %w\n%s", err, indent(string(out)))
	}
	targetDir := filepath.Join(destination, ".native-target")
	cmd := exec.CommandContext(ctx, cargo, "+1.94.0", "build", "--locked", "--release", "--manifest-path", "api/Cargo.toml", "--target", target)
	cmd.Dir = destination
	linkerKey := "CARGO_TARGET_" + strings.ToUpper(strings.ReplaceAll(target, "-", "_")) + "_LINKER"
	cmd.Env = append(os.Environ(), "CARGO_TARGET_DIR="+targetDir, ccKey+"="+compiler, linkerKey+"="+compiler)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("building the pinned Rust API: %w\n%s", err, indent(string(out)))
	}
	input, err := os.Open(filepath.Join(targetDir, target, "release", "komizo-api"))
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(filepath.Join(destination, "internal", "nativeapi", "payload.gz"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer output.Close()
	zipped := gzip.NewWriter(output)
	if _, err := io.Copy(zipped, input); err != nil {
		return err
	}
	if err := zipped.Close(); err != nil {
		return err
	}
	return output.Close()
}

func copyModule(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		output := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(output, 0700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("module source contains a nonregular file: %s", relative)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(file, input)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
