package box

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// RefuseScopedStart checks an explicitly declared credential generation under
// the shared application lock. It reads metadata only, never secret values.
func RefuseScopedStart(root, app string) error {
	if app == "" {
		return nil
	}
	path, err := appStatePath(root, app)
	if err != nil {
		return err
	}
	st, err := readState(path)
	if err != nil {
		return fmt.Errorf("could not read the app record, so nothing was started: %w", err)
	}
	definition, err := ParseScopedDefinition(st["SCOPED_ENV"], st["SCOPED_SCHEMA"], st["SCOPED_FILES"])
	if err != nil {
		return err
	}
	if definition == nil {
		return nil
	}
	lockPath := filepath.Join(root, "run/komizo", "deploy-"+app+".lock")
	if root == "" {
		lockPath = filepath.Join("/run/komizo", "deploy-"+app+".lock")
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return fmt.Errorf("scoped environment requires the shared app lock, so nothing was started: %w", err)
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("scoped environment requires the shared app lock, so nothing was started: %w", err)
	}
	defer lf.Close()
	if !flockExclusiveNB(lf.Fd()) {
		return fmt.Errorf("scoped environment requires the shared app lock, so nothing was started")
	}
	defer flockUnlock(lf.Fd())
	return checkScopedStart(root, app)
}

// LockDeploymentForStart checks scoped provenance under the same app and host
// locks that protect the entire lifecycle operation. Reacquiring the app lock
// inside that operation would refuse every scoped start or restart.
func LockDeploymentForStart(ctx context.Context, root, app string) (func(), error) {
	unlock, err := LockDeployment(ctx, root, app)
	if err != nil {
		return nil, err
	}
	if err := checkScopedStart(root, app); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// The caller retains the shared app lock for this check and any startup effects.
func checkScopedStart(root, app string) error {
	path, err := appStatePath(root, app)
	if err != nil {
		return err
	}
	st, err := readState(path)
	if err != nil {
		return fmt.Errorf("could not read the app record, so nothing was started: %w", err)
	}
	definition, err := ParseScopedDefinition(st["SCOPED_ENV"], st["SCOPED_SCHEMA"], st["SCOPED_FILES"])
	if err != nil {
		return err
	}
	if definition == nil {
		return nil
	}

	dir := st["APP_DIR"]
	id := st["SCOPED_GENERATION"]
	if !generationID(id) || dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("scoped env is not ready, so nothing was started")
	}
	secrets := filepath.Join(dir, "secrets")
	current, err := os.Readlink(filepath.Join(secrets, "current"))
	if err != nil || current != "generations/"+id {
		return fmt.Errorf("scoped env is not ready, so nothing was started")
	}
	gdir := filepath.Join(secrets, "generations", id)
	for _, name := range definition.Files {
		info, err := os.Lstat(filepath.Join(gdir, name))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("scoped env is not ready, so nothing was started")
		}
	}
	if !provenanceReady(gdir, id, *definition) {
		return fmt.Errorf("scoped env is not ready, so nothing was started")
	}
	return nil
}

func provenanceReady(gdir, id string, definition ScopedDefinition) bool {
	path := filepath.Join(gdir, "provenance")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
		return false
	}
	uid, ok := fileUID(info)
	if !ok || uid != 0 {
		return false
	}
	expected := definition.Marker(id)
	if info.Size() != int64(len(expected)) {
		return false
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, expected) {
		return false
	}
	return true
}

func generationID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
}
