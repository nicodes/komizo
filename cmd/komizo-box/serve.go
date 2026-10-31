package main

import (
	"context"
	"github.com/nicodes/komizo/internal/nativeapi"
	"os"
)

func runServe(args []string) error {
	return nativeapi.Run(context.Background(), append([]string{"serve"}, args...), os.Stdin, os.Stdout, os.Stderr)
}
