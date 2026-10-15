package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nicodes/komizo/box"
)

type scopedSpec struct {
	Version                   int      `json:"version"`
	Profile                   string   `json:"profile"`
	Schema                    int      `json:"schema"`
	Files                     []string `json:"files"`
	ProvisionScript           string   `json:"provision_script"`
	StatusScript              string   `json:"status_script"`
	provisionBody, statusBody []byte
}

func readScopedSpec(path string) (*scopedSpec, error) {
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 65536 {
		return nil, fmt.Errorf("scoped environment specification unavailable or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var spec scopedSpec
	if err := decoder.Decode(&spec); err != nil {
		return nil, fmt.Errorf("invalid scoped environment specification: %w", err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || spec.Version != 1 {
		return nil, fmt.Errorf("one versioned scoped environment specification is required")
	}
	if _, err := box.ParseScopedDefinition(spec.Profile, strconv.Itoa(spec.Schema), strings.Join(spec.Files, ",")); err != nil || spec.Profile == "" {
		return nil, fmt.Errorf("scoped environment specification requires an explicit valid definition")
	}
	read := func(name string) ([]byte, error) {
		if filepath.Base(name) != name || name == "." || name == ".." || !strings.HasSuffix(name, ".sh") {
			return nil, fmt.Errorf("scoped adapter must be a sibling shell script")
		}
		p := filepath.Join(filepath.Dir(path), name)
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
			return nil, fmt.Errorf("scoped adapter must be a bounded regular file")
		}
		body, err := os.ReadFile(p)
		if err != nil || !bytes.HasPrefix(body, []byte("#!")) {
			return nil, fmt.Errorf("scoped adapter requires a shebang")
		}
		return body, nil
	}
	spec.provisionBody, err = read(spec.ProvisionScript)
	if err != nil {
		return nil, err
	}
	spec.statusBody, err = read(spec.StatusScript)
	if err != nil {
		return nil, err
	}
	if len(spec.provisionBody)+len(spec.statusBody) > 64<<10 {
		return nil, fmt.Errorf("combined scoped adapters exceed transport bound")
	}
	return &spec, nil
}

func validScopedProfileName(value string) bool { return box.ValidScopedProfileName(value) }
func scopedSpecValue(spec *scopedSpec, key string) string {
	if spec == nil {
		return ""
	}
	switch key {
	case "schema":
		return strconv.Itoa(spec.Schema)
	case "files":
		return strings.Join(spec.Files, ",")
	case "provision":
		return base64.StdEncoding.EncodeToString(spec.provisionBody)
	case "status":
		return base64.StdEncoding.EncodeToString(spec.statusBody)
	}
	return ""
}
