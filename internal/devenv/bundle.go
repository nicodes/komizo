package devenv

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

const maxBundle = 48 << 10 // GitHub's per-secret limit.

// The bundle is the owner-maintained export allowlist. The workflow exposes no
// other secret or variable context to the exporter, even for direct dispatches.
type previewBundle struct {
	Version     int               `json:"version"`
	Environment string            `json:"environment"`
	Repository  string            `json:"repository"`
	Secrets     map[string]string `json:"secrets"`
	Variables   map[string]string `json:"variables"`
}

func parsePreviewBundle(data []byte, repository string) (previewBundle, error) {
	var bundle previewBundle
	invalid := errors.New("missing or invalid GHENV_PREVIEW_BUNDLE; expected a version 1 Preview bundle for this repository")
	if len(data) == 0 || len(data) > maxBundle || !repoName.MatchString(repository) {
		return bundle, invalid
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return bundle, invalid
	}
	// Check exact field names before Go's case-insensitive struct matching.
	// In particular, Unicode aliases such as "ſecrets" must not merge maps.
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 5 {
		return previewBundle{}, invalid
	}
	for name := range fields {
		switch name {
		case "version", "environment", "repository", "secrets", "variables":
		default:
			return previewBundle{}, invalid
		}
	}
	for _, name := range []string{"secrets", "variables"} {
		object := bytes.TrimSpace(fields[name])
		if len(object) == 0 || object[0] != '{' {
			return previewBundle{}, invalid
		}
		var entries map[string]json.RawMessage
		if json.Unmarshal(object, &entries) != nil {
			return previewBundle{}, invalid
		}
		for _, value := range entries {
			value = bytes.TrimSpace(value)
			if len(value) == 0 || value[0] != '"' {
				return previewBundle{}, invalid
			}
		}
	}
	if json.Unmarshal(data, &bundle) != nil {
		return previewBundle{}, invalid
	}
	if bundle.Version != 1 || bundle.Environment != "Preview" || bundle.Repository != repository {
		return previewBundle{}, invalid
	}
	for name, value := range bundle.Secrets {
		if !validBundleEntry(name, value) {
			return previewBundle{}, invalid
		}
		if _, duplicate := bundle.Variables[name]; duplicate {
			return previewBundle{}, invalid
		}
	}
	for name, value := range bundle.Variables {
		if !validBundleEntry(name, value) {
			return previewBundle{}, invalid
		}
	}
	return bundle, nil
}

func validBundleEntry(name, value string) bool {
	return envName.MatchString(name) && !strings.EqualFold(name, "GITHUB_TOKEN") && !strings.ContainsRune(value, 0)
}

// encoding/json otherwise accepts duplicate keys with last-value-wins semantics.
// Reject ambiguity before checking the scope marker or owner-maintained maps.
func uniqueJSON(decoder *json.Decoder, depth int) error {
	if depth > 4 {
		return errors.New("bundle JSON is too deeply nested")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	if delimiter != '{' {
		return errors.New("bundle containers must be objects")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || seen[strings.ToLower(key)] {
			return errors.New("duplicate bundle key")
		}
		seen[strings.ToLower(key)] = true
		if err := uniqueJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
