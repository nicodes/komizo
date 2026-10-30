package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var repositorySlug = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

type deploymentTarget struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	App  string `json:"app"`
}
type targetConfiguration struct {
	Version  int                         `json:"version"`
	Projects map[string]deploymentTarget `json:"projects"`
}

func targetPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "komizo", "targets.json"), nil
}
func readTargets() (targetConfiguration, error) {
	value := targetConfiguration{Version: 1, Projects: map[string]deploymentTarget{}}
	path, err := targetPath()
	if err != nil {
		return value, err
	}
	body, err := readJourneyFile(path, 1<<20, true)
	if errors.Is(err, os.ErrNotExist) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	if err = rejectDuplicateMembers(body); err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || value.Version != 1 || value.Projects == nil {
		return value, errors.New("invalid private project targets")
	}
	for repository, target := range value.Projects {
		if !repositorySlug.MatchString(repository) || validateApp(target.App) != nil || target.Port < 1 || target.Port > 65535 {
			return value, errors.New("invalid private project binding")
		}
		tgt, err := parseTarget(target.Host)
		if err != nil {
			return value, err
		}
		if err = validateHost(tgt.host); err != nil {
			return value, err
		}
	}
	return value, nil
}
func bindDeploymentTarget(repository string, tgt target, app string) error {
	if !repositorySlug.MatchString(repository) || validateApp(app) != nil {
		return errors.New("invalid repository binding")
	}
	config, err := readTargets()
	if err != nil {
		return err
	}
	binding := deploymentTarget{Host: tgt.addr(), Port: tgt.port, App: app}
	if previous, exists := config.Projects[repository]; exists && previous != binding {
		return errors.New("existing private project target differs; review the target file before moving an application")
	}
	config.Projects[repository] = binding
	path, err := targetPath()
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("target directory must be private and regular")
	}
	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, ".targets-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(append(body, '\n')); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

type deploymentConfiguration struct {
	Version    int      `json:"version"`
	Repository string   `json:"repository"`
	Images     []string `json:"images,omitempty"`
}

func readDeploymentConfiguration(directory string) (deploymentConfiguration, error) {
	var value deploymentConfiguration
	body, err := readJourneyFile(filepath.Join(directory, "komizo.json"), 1<<20, false)
	if err != nil {
		return value, fmt.Errorf("read deployment configuration: %w", err)
	}
	if err = rejectDuplicateMembers(body); err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || value.Version != 1 || !repositorySlug.MatchString(value.Repository) || len(value.Images) > 16 {
		return value, errors.New("komizo.json must contain only a version-1 deployment repository and optional image references")
	}
	seen := map[string]bool{}
	for _, image := range value.Images {
		resolved := strings.ReplaceAll(image, "{revision}", strings.Repeat("a", 40))
		if image == "" || seen[image] || len(image) > 2048 || !onlyChars(resolved, imageChars+"@=") {
			return value, errors.New("deployment images require distinct valid references with only an optional {revision} template")
		}
		seen[image] = true
	}
	return value, nil
}

func deploymentBinding(directory string) (deploymentConfiguration, deploymentTarget, error) {
	m, err := readDeploymentConfiguration(directory)
	if err != nil {
		return m, deploymentTarget{}, err
	}
	config, err := readTargets()
	if err != nil {
		return m, deploymentTarget{}, err
	}
	binding, exists := config.Projects[m.Repository]
	if !exists {
		return m, binding, errors.New("no private target for this repository; an operator must run komizo setup --host HOST --definition FILE, or supply --host and --app explicitly")
	}
	return m, binding, nil
}
func defaultDeploymentTarget(directory string, host *string, port *int, app *string, fs *flag.FlagSet) (deploymentConfiguration, error) {
	if *host != "" {
		return deploymentConfiguration{}, nil
	}
	m, binding, err := deploymentBinding(directory)
	if err != nil {
		return m, err
	}
	if *app != "" && *app != binding.App {
		return m, errors.New("application differs from the private repository binding")
	}
	if fs != nil && portWasSet(fs) && *port != binding.Port {
		return m, errors.New("SSH port differs from the private deployment binding; select the host explicitly to override it")
	}
	*host, *app = binding.Host, binding.App
	if fs == nil {
		*port = binding.Port
	} else if !portWasSet(fs) {
		if err := fs.Set("port", strconv.Itoa(binding.Port)); err != nil {
			return m, err
		}
	}
	return m, nil
}
func deploymentRevision(directory string) (string, error) {
	c := commandExec("git", "-C", directory, "status", "--porcelain", "--untracked-files=normal")
	body, err := c.Output()
	if err != nil {
		return "", err
	}
	if len(bytes.TrimSpace(body)) != 0 {
		return "", errors.New("commit project changes before selecting a deployment revision")
	}
	c = commandExec("git", "-C", directory, "rev-parse", "HEAD")
	body, err = c.Output()
	if err != nil {
		return "", err
	}
	revision := strings.TrimSpace(string(body))
	if !exactHex(revision, 40) {
		return "", errors.New("exact source revision is required")
	}
	return revision, nil
}
