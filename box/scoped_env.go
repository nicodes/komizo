package box

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// RefuseScopedStart stops start and restart for fields-postgres-v2 unless the
// current generation still matches the id recorded at provision and api.env
// alone holds a production CLERK_SECRET_KEY. A withdrawn fields-postgres-v1
// record is not treated as ready. Other apps are untouched. File bytes are
// not included in errors. A lock that cannot be taken is a refusal, not a
// start beside a deploy.
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
	switch st["SCOPED_ENV"] {
	case "fields-postgres-v1":
		return fmt.Errorf("fields-postgres-v1 is withdrawn, so nothing was started")
	case "fields-postgres-v2":
	default:
		return nil
	}
	lockPath := filepath.Join(root, "run/komizo", "deploy-"+app+".lock")
	if root == "" {
		lockPath = filepath.Join("/run/komizo", "deploy-"+app+".lock")
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return fmt.Errorf("fields-postgres-v2 requires the shared app lock, so nothing was started: %w", err)
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("fields-postgres-v2 requires the shared app lock, so nothing was started: %w", err)
	}
	defer lf.Close()
	if !flockExclusiveNB(lf.Fd()) {
		return fmt.Errorf("fields-postgres-v2 requires the shared app lock, so nothing was started")
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
	if !v2Layout(gdir) {
		return fmt.Errorf("scoped env is not ready, so nothing was started")
	}
	return nil
}

func v2Layout(gdir string) bool {
	api, err := os.ReadFile(filepath.Join(gdir, "api.env"))
	if err != nil || !oneProductionSecret(api) {
		return false
	}
	for _, name := range []string{"postgres.env", "migrate.env", "godot-api.env"} {
		body, err := os.ReadFile(filepath.Join(gdir, name))
		if err != nil || bytes.Contains(body, []byte("CLERK_SECRET_KEY")) {
			return false
		}
	}
	required := map[string][]string{
		"postgres.env":  {"POSTGRES_PASSWORD", "REVIK_MIGRATOR_PASSWORD", "REVIK_APP_PASSWORD", "REVIK_BACKUP_PASSWORD"},
		"migrate.env":   {"DATABASE_MIGRATION_URL"},
		"api.env":       {"DATABASE_URL", "WS_SECRET", "CLERK_ISSUER", "CLERK_JWKS_URL", "CLERK_AUTHORIZED_PARTIES", "CLERK_SECRET_KEY"},
		"godot-api.env": {"WS_SECRET"},
	}
	files := map[string][]byte{"api.env": api}
	for _, name := range []string{"postgres.env", "migrate.env", "godot-api.env"} {
		body, err := os.ReadFile(filepath.Join(gdir, name))
		if err != nil {
			return false
		}
		files[name] = body
	}
	for name, keys := range required {
		for _, key := range keys {
			if !hasKey(files[name], key) {
				return false
			}
		}
	}
	return true
}

func hasKey(body []byte, key string) bool {
	prefix := []byte(key + "=")
	for _, line := range bytes.Split(body, []byte("\n")) {
		if bytes.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func oneProductionSecret(body []byte) bool {
	n := 0
	for _, line := range bytes.Split(body, []byte("\n")) {
		if !bytes.Contains(line, []byte("CLERK_SECRET_KEY")) {
			continue
		}
		prefix := []byte("CLERK_SECRET_KEY=")
		if !bytes.HasPrefix(line, prefix) || !productionSecret(line[len(prefix):]) {
			return false
		}
		n++
	}
	return n == 1
}

func productionSecret(s []byte) bool {
	if len(s) < 9 || len(s) > 4096 {
		return false
	}
	if bytes.HasPrefix(s, []byte("sk_test_")) || !bytes.HasPrefix(s, []byte("sk_live_")) {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c > '~' || c == '"' || c == '#' || c == '$' || c == '\'' || c == '\\' || c == '`' {
			return false
		}
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
