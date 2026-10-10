package box

import (
	"context"
	"fmt"
	"strings"
)

// The proxy is the only shared member. Each preview's gateway is on its own
// internal network, so it cannot use Docker DNS or direct TCP to its neighbours.
func ensurePreviewIngress(ctx context.Context, run previewRun, project, proxy string) (string, error) {
	network := project + "-ingress"
	owner, err := run(ctx, "", "network", "inspect", network, "--format", `{{index .Labels "io.komizo.preview"}}`)
	if err != nil {
		if _, err = run(ctx, "", "network", "create", "--internal", "--label", previewNetworkLabel+"="+project, network); err != nil {
			return "", fmt.Errorf("preview ingress creation failed: %w", err)
		}
	} else if strings.TrimSpace(owner) != project {
		return "", fmt.Errorf("preview ingress belongs to another workload")
	}
	attached, err := run(ctx, "", "inspect", proxy, "--format", `{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}`)
	if err != nil {
		return "", err
	}
	for _, name := range strings.Fields(attached) {
		if name == network {
			return network, nil
		}
	}
	if _, err = run(ctx, "", "network", "connect", network, proxy); err != nil {
		return "", err
	}
	return network, nil
}

func removePreviewIngress(ctx context.Context, run previewRun, project, proxy string) error {
	network := project + "-ingress"
	owner, err := run(ctx, "", "network", "inspect", network, "--format", `{{index .Labels "io.komizo.preview"}}`)
	if err != nil {
		return nil
	} // legacy previews used the common ingress
	if strings.TrimSpace(owner) != project {
		return fmt.Errorf("preview ingress removal refused: ownership differs")
	}
	attached, err := run(ctx, "", "inspect", proxy, "--format", `{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}`)
	if err != nil {
		return err
	}
	for _, name := range strings.Fields(attached) {
		if name == network {
			if _, err = run(ctx, "", "network", "disconnect", "--force", network, proxy); err != nil {
				return err
			}
		}
	}
	_, err = run(ctx, "", "network", "rm", network)
	return err
}
