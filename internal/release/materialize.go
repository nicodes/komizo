package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
)

// BindSecretVersions replaces artifact-supplied secret version claims with the
// opaque versions atomically materialized beside the host's secret values.
// Secret bytes never enter this function or the returned model.
func BindSecretVersions(data []byte, versions map[string]string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, errors.New("invalid normalized model")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("normalized model must contain one JSON document")
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("normalized model must be an object")
	}
	extension, ok := root["x-komizo"].(map[string]any)
	if !ok {
		return nil, errors.New("normalized model has no x-komizo metadata")
	}
	services, ok := root["services"].(map[string]any)
	if !ok {
		return nil, errors.New("normalized model has no services")
	}
	wanted := map[string]any{}
	for _, serviceName := range slices.Sorted(maps.Keys(services)) {
		service, ok := services[serviceName].(map[string]any)
		if !ok {
			return nil, errors.New("normalized service is not an object")
		}
		if grants, _ := service["secrets"].([]any); len(grants) != 0 {
			return nil, errors.New("profile rollout supports host-materialized environment secrets, not model-selected secret files")
		}
		environment, _ := service["environment"].(map[string]any)
		for variable, raw := range environment {
			value, ok := raw.(string)
			if !ok || !strings.Contains(value, "$") {
				continue
			}
			name, exact := environmentSecretReference(value)
			version := versions[name]
			if !exact || variable != name || version == "" {
				return nil, errors.New("secret environment values must be exact same-name host-materialized references")
			}
			wanted[name] = version
		}
	}
	if len(wanted) != len(versions) {
		return nil, errors.New("host secret versions must match the model's complete granted secret set")
	}
	extension["secret_versions"] = wanted
	return json.Marshal(root)
}

func environmentSecretReference(value string) (string, bool) {
	if len(value) < 4 || !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") || strings.Count(value, "$") != 1 {
		return "", false
	}
	name := value[2 : len(value)-1]
	if !validEnvironmentName(name) {
		return "", false
	}
	return name, true
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
