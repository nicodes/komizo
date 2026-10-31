package app

import (
	"context"
	"github.com/nicodes/komizo/internal/nativeapi"
	"os"
)

// RunUI launches the Rust/Axum API embedded in the CLI. The API owns local
// file reads, request validation, static assets and finite lifecycle dispatch.
func RunUI(args []string) error {
	argv := append([]string{"ui"}, args...)
	return nativeapi.Run(context.Background(), argv, os.Stdin, commandOutput(), commandFlags())
}
