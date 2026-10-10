package box

import (
	"context"
	"fmt"
	"strings"
)

const previewNetworkLabel = "io.komizo.preview"

func ensurePreviewBackend(ctx context.Context, run previewRun, project string, database bool) error {
	network := project + "-backend"
	owner, err := run(ctx, "", "network", "inspect", network, "--format", `{{index .Labels "io.komizo.preview"}}`)
	if err != nil {
		if _, err = run(ctx, "", "network", "create", "--label", previewNetworkLabel+"="+project, network); err != nil {
			return fmt.Errorf("preview backend creation failed: %w", err)
		}
	} else if strings.TrimSpace(owner) != project {
		return fmt.Errorf("preview backend name belongs to an unapproved network")
	}
	if database {
		attached, err := run(ctx, "", "inspect", PreviewDBContainer, "--format", `{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}`)
		if err != nil {
			return err
		}
		for _, name := range strings.Fields(attached) {
			if name == network {
				return nil
			}
		}
		if _, err = run(ctx, "", "network", "connect", network, PreviewDBContainer); err != nil {
			return fmt.Errorf("preview database attachment failed: %w", err)
		}
	}
	return nil
}
func removePreviewBackend(ctx context.Context, run previewRun, project string, database bool) error {
	network := project + "-backend"
	owner, err := run(ctx, "", "network", "inspect", network, "--format", `{{index .Labels "io.komizo.preview"}}`)
	if err != nil {
		return nil
	} // older previews did not own this network
	if strings.TrimSpace(owner) != project {
		return fmt.Errorf("preview backend removal refused: ownership differs")
	}
	if database {
		if _, err = run(ctx, "", "network", "disconnect", "--force", network, PreviewDBContainer); err != nil {
			return err
		}
	}
	_, err = run(ctx, "", "network", "rm", network)
	return err
}
