//go:build !linux

package main

func applySmallHostKernelMemory(string, int64) error { return nil }
