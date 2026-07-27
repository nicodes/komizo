package main

import (
	"fmt"
	"strings"
)

// Everything here ends up either single-quoted into a remote command line or
// used as a path component on the server. Constraining the character sets is
// what makes that quoting sufficient, so these run before anything connects.

func onlyChars(s, allowed string) bool {
	for _, r := range s {
		if !strings.ContainsRune(allowed, r) {
			return false
		}
	}
	return true
}

const (
	appChars   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	userChars  = appChars + "."
	hostChars  = userChars + ":"
	imageChars = userChars + ":/"
	pathChars  = userChars + "/"
)

func validateApp(s string) error {
	if s == "" || !onlyChars(s, appChars) {
		return fmt.Errorf("--app must be letters, digits, underscore or hyphen; got %q", s)
	}
	// Reserved for komizo's own directories under /srv -- /srv/_proxy today, and
	// room for more without another round of renaming. Refusing the whole prefix
	// rather than the single name means the inventory can tell an app from an
	// internal directory by its name alone.
	if strings.HasPrefix(s, "_") {
		return fmt.Errorf("app names starting with %q are reserved for komizo; got %q", "_", s)
	}
	return nil
}

func validateUser(s string) error {
	if s == "" || !onlyChars(s, userChars) {
		return fmt.Errorf("--user must be letters, digits, dot, underscore or hyphen; got %q", s)
	}
	return nil
}

func validateHost(s string) error {
	if s == "" || !onlyChars(s, hostChars) {
		return fmt.Errorf("hostname contains unexpected characters: %q", s)
	}
	return nil
}

func validateAppDir(s string) error {
	if s == "" {
		return nil
	}
	if !strings.HasPrefix(s, "/") {
		return fmt.Errorf("--app-dir must be an absolute path, got %q", s)
	}
	if !onlyChars(s, pathChars) {
		return fmt.Errorf("--app-dir contains characters that are not allowed: %q", s)
	}
	return nil
}

func validateNetwork(s string) error {
	if s == "" {
		return nil
	}
	if !onlyChars(s, userChars) {
		return fmt.Errorf("--network must be letters, digits, dot, underscore or hyphen; got %q", s)
	}
	return nil
}

// validateConfigImage rejects a tag or digest. The deploy supplies the tag; one
// baked in here would silently pin every deploy to a single version.
//
// A tag is a colon AFTER the last slash -- a colon before it is a registry
// port, as in registry.internal:5000/app-config, which is legitimate.
func validateConfigImage(s string) error {
	if s == "" {
		return fmt.Errorf("--config is required, e.g. --config ghcr.io/you/myapp-config\n" +
			"\n" +
			"    It is where the host looks for each deploy's compose.yml. Pinning it\n" +
			"    on the server is what stops a leaked deploy key redirecting the host\n" +
			"    at an image an attacker controls.")
	}
	if strings.Contains(s, "@") {
		return fmt.Errorf("--config must not include a digest, got %q", s)
	}
	if !onlyChars(s, imageChars) {
		return fmt.Errorf("--config contains characters that are not valid in an image reference: %q", s)
	}
	last := s
	if i := strings.LastIndex(s, "/"); i >= 0 {
		last = s[i+1:]
	}
	if strings.Contains(last, ":") {
		return fmt.Errorf("--config must not include a tag (got %q); the deploy supplies it", s)
	}
	return nil
}
