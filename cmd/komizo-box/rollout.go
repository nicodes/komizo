package main

import (
	"errors"
	"os"

	"github.com/nicodes/komizo/internal/gateway"
	"github.com/nicodes/komizo/internal/rollout"
)

func runLocalRollout(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("local rollout requires the root operator; no deploy-user delegation is granted")
	}
	ctx, cancel := signalContext()
	defer cancel()
	return rollout.Command(ctx, args, os.Stdin, os.Stdout, os.Stderr)
}

func runGateway(args []string) error {
	ctx, cancel := signalContext()
	defer cancel()
	return gateway.Command(ctx, args, os.Stderr)
}
