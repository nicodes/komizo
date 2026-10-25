package devenv

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var repoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`)

type options struct {
	Repo, Environment, Ref, Secrets, Variables string
	Timeout                                    time.Duration
	Command                                    []string
	CleanEnvironment                           bool
}

func requestedNames(secrets, variables string) ([]string, error) {
	var result []string
	for _, group := range []string{secrets, variables} {
		if group == "" {
			continue
		}
		for _, name := range strings.Split(group, ",") {
			if !envName.MatchString(name) || strings.EqualFold(name, "GITHUB_TOKEN") {
				return nil, errors.New("names must be environment variable identifiers; GITHUB_TOKEN cannot be exported")
			}
			if slices.Contains(result, name) {
				return nil, fmt.Errorf("duplicate name %s", name)
			}
			result = append(result, name)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("request at least one name with --secrets or --vars")
	}
	return result, nil
}

func selectValues(secrets, variables map[string]string, secretNames, variableNames string) (map[string]string, error) {
	names, err := requestedNames(secretNames, variableNames)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(names))
	for i, group := range []string{secretNames, variableNames} {
		if group == "" {
			continue
		}
		source := secrets
		if i == 1 {
			source = variables
		}
		for _, name := range strings.Split(group, ",") {
			value, ok := source[name]
			if !ok {
				return nil, fmt.Errorf("requested name %s is unavailable in this workflow environment", name)
			}
			if strings.ContainsRune(value, 0) {
				return nil, fmt.Errorf("%s contains a NUL byte and cannot be an environment value", name)
			}
			result[name] = value
		}
	}
	return result, nil
}

func commandEnvironment(base []string, values map[string]string) []string {
	result := make([]string, 0, len(base)+len(values))
	for _, item := range base {
		name, _, _ := strings.Cut(item, "=")
		if _, replace := values[name]; !replace {
			result = append(result, item)
		}
	}
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}
