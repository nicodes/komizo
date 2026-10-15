package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"regexp"

	"github.com/nicodes/komizo/box"
)

func runPreviewConfigure(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("preview configure requires the host operator")
	}
	fs := flag.NewFlagSet("preview configure", flag.ContinueOnError)
	app := fs.String("app", "", "registered application")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("preview configure accepts only --app")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`).MatchString(*app) {
		return errors.New("invalid registered application")
	}
	p, err := readWorkloadPolicy("/etc/komizo/workloads/" + *app + ".json")
	if err != nil {
		return err
	}
	if p.App != *app {
		return errors.New("preview profile app differs from protected policy")
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, (128<<10)+1))
	if err != nil {
		return err
	}
	if _, err := box.ParsePreviewProfile(body); err != nil {
		return err
	}
	if err := configurePreviewProfile(context.Background(), *app, body); err != nil {
		return err
	}
	return previewProfileReceipt(*app, body)
}
func configurePreviewProfile(ctx context.Context, app string, body []byte) error {
	// Hold the same host/application and preview exclusion as an up/down.
	return box.ConfigurePreviewProfile(ctx, app, body)
}

// Retain small public output: configuration contains no credentials, and its
// hash binds the exact reviewed policy used by future preview records.
func previewProfileReceipt(app string, body []byte) error {
	digest := sha256.Sum256(body)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"configured": true, "app": app, "sha256": hex.EncodeToString(digest[:])})
}
