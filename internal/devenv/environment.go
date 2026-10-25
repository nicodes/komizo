package devenv

import "strings"

// Authentication for gh still uses the original process environment. Only the
// application gets this restricted environment; unrelated credentials, dotenv
// overrides, loader hooks and build flags are deliberately not inherited.
func developmentEnvironment(base []string, values map[string]string) []string {
	var result []string
	for _, item := range base {
		name, _, _ := strings.Cut(item, "=")
		switch name {
		case "HOME", "USER", "LOGNAME", "PATH", "SHELL", "PWD", "TMPDIR", "TMP", "TEMP",
			"TERM", "COLORTERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION", "LANG", "LC_ALL", "LC_CTYPE",
			"DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
			"SSH_AUTH_SOCK", "GOROOT", "GOPATH", "GOMODCACHE", "GOCACHE", "GOTOOLCHAIN",
			"BUN_INSTALL", "BUN_INSTALL_CACHE_DIR", "MISE_DATA_DIR", "MISE_CACHE_DIR", "MISE_CONFIG_DIR",
			"MISE_STATE_DIR", "MISE_TRUSTED_CONFIG_PATHS", "MISE_INSTALLS_DIR":
			result = append(result, item)
		}
	}
	injected := make(map[string]string, len(values)+1)
	for name, value := range values {
		injected[name] = value
	}
	// Expo otherwise loads .env after the handoff and can restore stale values.
	injected["EXPO_NO_DOTENV"] = "1"
	return commandEnvironment(result, injected)
}
