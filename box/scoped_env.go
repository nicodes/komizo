package box

import (
	"fmt"
	"os"
	"path/filepath"
)

// RefuseScopedStart stops start and restart for fields-postgres-v1 unless the
// current generation still matches the id recorded at provision. It does not
// read env files. Other apps are untouched. A lock that cannot be taken is a
// refusal, not a start beside a deploy.
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
	if st["SCOPED_ENV"] != "fields-postgres-v1" {
		return nil
	}
	lockPath := filepath.Join(root, "run/komizo", "deploy-"+app+".lock")
	if root == "" {
		lockPath = filepath.Join("/run/komizo", "deploy-"+app+".lock")
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return fmt.Errorf("fields-postgres-v1 requires the shared app lock, so nothing was started: %w", err)
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("fields-postgres-v1 requires the shared app lock, so nothing was started: %w", err)
	}
	defer lf.Close()
	if !flockExclusiveNB(lf.Fd()) {
		return fmt.Errorf("fields-postgres-v1 requires the shared app lock, so nothing was started")
	}
	defer flockUnlock(lf.Fd())

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
	for _, name := range []string{"postgres.env", "migrate.env", "api.env", "godot-api.env"} {
		info, err := os.Lstat(filepath.Join(gdir, name))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("scoped env is not ready, so nothing was started")
		}
	}
	return nil
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
