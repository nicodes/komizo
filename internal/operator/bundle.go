// Package operator distributes the privileged merge operator from one owner.
// The assets are embedded in authenticated komizo releases; agent configuration
// repositories neither implement nor replace this authority.
package operator

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

//go:embed assets/*
var assets embed.FS

var names = []string{"fleet_operator.py", "fleet_broker.py", "fleet_publisher.py", "fleet-operator.service", "fleet-operator.socket"}

// Plan identifies every byte in the operator bundle without installing it.
func Plan() (map[string]string, error) {
	out := map[string]string{}
	for _, name := range names {
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		out[name] = hex.EncodeToString(sum[:])
	}
	return out, nil
}

// Export creates a new private staging directory. It cannot overwrite installed
// code, credentials, configuration or a previous staging directory.
func Export(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return errors.New("operator export requires a new absolute canonical directory")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	for _, name := range names {
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(body)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
