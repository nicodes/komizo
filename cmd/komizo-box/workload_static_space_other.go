//go:build !linux

package main

import (
	"errors"
	"github.com/nicodes/komizo/internal/workload"
)

func staticSpace(string, workload.StaticLimits) error {
	return errors.New("static extraction requires the Linux host executor")
}
