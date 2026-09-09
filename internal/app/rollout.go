package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/nicodes/komizo/internal/gateway"
	"github.com/nicodes/komizo/internal/rollout"
)

func RunRollout(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return rollout.Command(ctx, args, os.Stdout, os.Stderr)
}

func RunGateway(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return gateway.Command(ctx, args, os.Stderr)
}
