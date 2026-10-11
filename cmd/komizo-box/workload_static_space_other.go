//go:build !linux

package main

import "errors"

func staticSpace(string) error {
	return errors.New("static extraction requires the Linux host executor")
}
