package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/nicodes/komizo/internal/agent"
)

// Only embedded release bytes may be exported; this never builds or downloads.
func RunArtifact(args []string) error {
	fs := flag.NewFlagSet("artifact", flag.ContinueOnError)
	arch := fs.String("arch", "", "embedded Linux architecture: amd64 or arm64")
	output := fs.String("output", "", "new output file (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" || (*arch != "amd64" && *arch != "arm64") {
		return errors.New("artifact requires an exact architecture and new output file")
	}
	body, err := agent.For(*arch)
	if err != nil {
		return err
	}
	if err := writeAgentArtifact(*output, body); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	receipt, _ := json.Marshal(map[string]string{"version": versionText(), "architecture": *arch, "sha256": hex.EncodeToString(sum[:]), "stamp": agent.Stamp()})
	fmt.Println(string(receipt))
	return nil
}

func writeAgentArtifact(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return err
	}
	defer file.Close()
	identity, err := file.Stat()
	if err != nil {
		return err
	}
	accepted := false
	defer func() {
		if !accepted {
			if current, err := os.Lstat(path); err == nil && os.SameFile(identity, current) {
				_ = os.Remove(path)
			}
		}
	}()
	if _, err = file.Write(body); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	accepted = true
	return nil
}
