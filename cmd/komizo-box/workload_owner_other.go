//go:build windows || plan9

package main

import "os"

func workloadRootOwner(os.FileInfo) bool { return false }
