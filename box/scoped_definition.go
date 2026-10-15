package box

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ScopedDefinition is operator-owned metadata, independent of application,
// database, identity provider and environment variable names.
type ScopedDefinition struct {
	Profile string
	Schema  int
	Files   []string
}

var scopedProfileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
var scopedFileName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)

func ValidScopedProfileName(value string) bool { return scopedProfileName.MatchString(value) }

func ParseScopedDefinition(profile, schema, files string) (*ScopedDefinition, error) {
	if profile == "" {
		if schema != "" || files != "" {
			return nil, fmt.Errorf("unscoped app has scoped metadata")
		}
		return nil, nil
	}
	n, err := strconv.Atoi(schema)
	if !scopedProfileName.MatchString(profile) || err != nil || n < 1 || n > 1000000 {
		return nil, fmt.Errorf("scoped environment needs an explicit valid profile and schema")
	}
	names := strings.Split(files, ",")
	if len(names) < 1 || len(names) > 64 {
		return nil, fmt.Errorf("scoped environment needs a bounded file declaration")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !scopedFileName.MatchString(name) || filepath.Base(name) != name || name == "." || name == ".." || name == "provenance" || seen[name] {
			return nil, fmt.Errorf("scoped environment has an unsafe or duplicate file declaration")
		}
		seen[name] = true
	}
	return &ScopedDefinition{Profile: profile, Schema: n, Files: names}, nil
}

func (s ScopedDefinition) Marker(generation string) []byte {
	return []byte(fmt.Sprintf("profile=%s\nschema=%d\ngeneration=%s\n", s.Profile, s.Schema, generation))
}
