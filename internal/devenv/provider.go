package devenv

import (
	"context"
	"github.com/nicodes/ghenv/provider"
	"strings"
	"time"
)

// Prepare uses the shared ghenv provider; Komizo owns the checkout session.
func Prepare(ctx context.Context, profile, mode string, base []string) ([]string, error) {
	return provider.Prepare(ctx, profile, mode, base)
}

func Launch(command, environment []string) error {
	return launchEnvironment(command, environment, 5*time.Second)
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
