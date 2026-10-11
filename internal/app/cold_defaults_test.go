package app

import (
	"strings"
	"testing"
)

func TestColdSetupAcceptsPinnedProxyBeforeHostValidation(t *testing.T) {
	for name, run := range map[string]func([]string) error{"init": RunInit, "update": RunUpdate} {
		t.Run(name, func(t *testing.T) {
			err := run([]string{"--host", "invalid;host"})
			if err == nil || !strings.Contains(err.Error(), "hostname contains unexpected characters") {
				t.Fatalf("default pinned proxy did not reach host validation: %v", err)
			}
			err = run([]string{"--host", "invalid;host", "--proxy-image", defaultProxy + ";foreign"})
			if err == nil || !strings.Contains(err.Error(), "--proxy-image") {
				t.Fatalf("unsafe proxy image was admitted: %v", err)
			}
		})
	}
}
