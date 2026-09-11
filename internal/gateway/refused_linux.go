//go:build linux

package gateway

import (
	"errors"
	"syscall"
)

func connectionRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
