// Package servicehealth shares required-service semantics between activation
// readiness and ongoing observation. Process state alone cannot prove readiness.
package servicehealth

type Desired struct {
	Restart     string       `json:"restart"`
	Profiles    []string     `json:"profiles"`
	Healthcheck *Healthcheck `json:"healthcheck"`
}

type Healthcheck struct {
	Test    []string `json:"test"`
	Disable bool     `json:"disable"`
}

func Ready(service Desired, state string, exitCode int, health string) bool {
	if service.Restart == "no" && state == "exited" && exitCode == 0 {
		return true
	}
	if state != "running" {
		return false
	}
	required := service.Healthcheck != nil && !service.Healthcheck.Disable && len(service.Healthcheck.Test) > 0 && service.Healthcheck.Test[0] != "NONE"
	return (health == "" && !required) || health == "healthy"
}
