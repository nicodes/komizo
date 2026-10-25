package devenv

import (
	"context"
	"time"
)

// Prepare validates the development policy and returns a clean child environment.
// The GitHub client uses the original parent credentials only for the handoff.
func Prepare(ctx context.Context, profile, mode string, base []string) ([]string, error) {
	p, err := readProject(profile)
	if err != nil {
		return nil, err
	}
	return projectEnvironment(ctx, p, mode, base, func(ctx context.Context, o options) (map[string]string, error) {
		return fetchEnvironment(ctx, ghAPI, o)
	})
}

// Launch owns the child's process group, terminal and bounded descendant cleanup.
func Launch(command, environment []string) error {
	return launchEnvironment(command, environment, 5*time.Second)
}
