package project

import (
	"encoding/json"
	"sort"
)

// Description exposes capability metadata without running project commands or
// materializing tools. Credential values and fixed development settings are
// deliberately absent, so a private fleet audit needs no product execution.
type Description struct {
	Version    int                        `json:"version"`
	Tools      map[string]json.RawMessage `json:"tools"`
	Repository string                     `json:"repository,omitempty"`
	Recipe     string                     `json:"recipe"`
	Platform   string                     `json:"platform"`
	Stages     map[string]bool            `json:"stages"`
	Tasks      []string                   `json:"tasks"`
	Commands   map[string][]string        `json:"commands"`
}

func Describe(root, platform string) (Description, error) {
	var d Description
	m, data, err := Read(root)
	if err != nil {
		return d, err
	}
	if err = CheckLock(root, platform, data, m); err != nil {
		return d, err
	}
	contract, err := m.Contract()
	if err != nil {
		return d, err
	}
	d = Description{Version: 1, Repository: m.Repository, Recipe: m.Recipe, Platform: platform,
		Stages: map[string]bool{}, Tasks: []string{}, Commands: map[string][]string{}, Tools: m.ToolsForRecipe()}
	stages := contract["stages"].(map[string]json.RawMessage)
	for name, value := range stages {
		var commands [][]string
		d.Stages[name] = json.Unmarshal(value, &commands) == nil
	}
	for name := range m.Tasks {
		d.Tasks = append(d.Tasks, name)
	}
	sort.Strings(d.Tasks)
	for _, name := range []string{"dev", "check", "preview", "deploy", "status"} {
		d.Commands[name] = []string{"komizo", name}
	}
	return d, nil
}
