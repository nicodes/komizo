package release

import (
	"bytes"
	"encoding/json"
	"errors"
)

// CandidateCompose produces a private, single-candidate Compose document from
// the already validated model. It does not overwrite the source app definition.
// The unique service key prevents Compose from installing the original service
// DNS alias beside an active instance. Network provisioning remains separate.
func (m *Model) CandidateCompose(service, instance, app, network string, labels map[string]string) ([]byte, error) {
	if m.private == nil || !validName(instance) || !validName(app) || !validName(network) || m.Policies[service].Mode != "http" {
		return nil, errors.New("candidate needs a resolved HTTP model and valid scope")
	}
	services := m.private["services"].(map[string]any)
	source, ok := services[service].(map[string]any)
	if !ok {
		return nil, errors.New("candidate service is not in the resolved model")
	}
	if err := m.CheckApp(app); err != nil {
		return nil, err
	}
	if networks, ok := source["networks"].(map[string]any); !ok || len(networks) != 1 {
		return nil, errors.New("HTTP execution currently requires one explicit app-private network")
	} else {
		definitions, _ := m.private["networks"].(map[string]any)
		for name, raw := range networks {
			options, _ := raw.(map[string]any)
			definition, _ := definitions[name].(map[string]any)
			if len(options) != 0 || definition["name"] != network {
				return nil, errors.New("candidate network must match the declared stable private network")
			}
		}
	}
	// Do not mutate the model; copying through JSON also detaches nested maps.
	encoded, _ := json.Marshal(source)
	var copy map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&copy); err != nil {
		return nil, errors.New("cannot copy canonical service")
	}
	delete(copy, "depends_on") // controller gates dependencies/readiness instead
	copy["container_name"] = instance
	copy["networks"] = map[string]any{"private": map[string]any{"aliases": []string{instance}}}
	mergedLabels, _ := copy["labels"].(map[string]any)
	if mergedLabels == nil {
		mergedLabels = map[string]any{}
	}
	for name, value := range labels {
		mergedLabels[name] = value
	}
	copy["labels"] = mergedLabels
	document := map[string]any{
		"name":     app,
		"services": map[string]any{instance: copy},
		"networks": map[string]any{"private": map[string]any{"external": true, "name": network}},
	}
	for _, kind := range []string{"volumes", "configs"} {
		selected, err := referencedResources(kind, source[kind], m.private[kind])
		if err != nil {
			return nil, err
		}
		if kind == "volumes" {
			for _, raw := range selected {
				definition, _ := raw.(map[string]any)
				name, _ := definition["name"].(string)
				if definition["external"] != true || name == "" {
					return nil, errors.New("candidate data volumes must already exist with explicit external names")
				}
			}
		}
		if len(selected) != 0 {
			document[kind] = selected
		}
	}
	if grants, ok := source["secrets"].([]any); ok && len(grants) != 0 {
		selected := map[string]any{}
		definitions, _ := m.private["secrets"].(map[string]any)
		for _, grant := range grants {
			name := grant.(map[string]any)["source"].(string)
			selected[name] = definitions[name]
		}
		document["secrets"] = selected
	}
	return json.Marshal(document)
}

func (m *Model) CheckApp(app string) error {
	if m.private == nil || !validName(app) {
		return errors.New("unresolved application scope")
	}
	if name, ok := m.private["name"].(string); ok && name != app {
		return errors.New("Compose project does not match the authorized app")
	}
	return nil
}
