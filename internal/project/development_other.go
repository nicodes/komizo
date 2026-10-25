//go:build !linux && !darwin

package project

import "errors"

func developmentLease(string) (func(), error) {
	return nil, errors.New("local development requires Linux or macOS")
}
