package app

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// The shell komizo pipes to a server runs as ROOT, and nothing here used to
// parse any of it.
//
// That is not a gap in coverage, it is the gap that mattered: a script is
// perfectly capable of being wrong in a way that reads correctly. So everything
// generated is syntax-checked as the box will read it -- after substitution, as
// a whole file -- rather than being asserted about as text.
//
// What this package still generates is the PROVISIONING half. The half that
// read a box was shell too, and is now Go: see internal/box, where the same
// question is settled by running the probes instead.

func needs(t *testing.T, tool string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s is not installed", tool)
	}
}

// shellCheck runs `sh -n`, which parses without executing.
func shellCheck(t *testing.T, name, script string) {
	t.Helper()
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%s is not valid shell: %v\n%s", name, err, out)
	}
}

// The two scripts komizo writes to the box are templates inside alpine.sh, so
// checking alpine.sh itself says nothing about them: to the outer shell they
// are the body of a quoted heredoc, which parses whatever it contains.
//
// They are what runs as root every time anybody deploys, so they get checked
// the way the box will read them -- after substitution, as a whole file.
func TestTheScriptsInstalledOnTheBoxAreValidShell(t *testing.T) {
	needs(t, "sh")
	subs := strings.NewReplacer(
		"__APP_NAME__", "blog",
		"__APP_DIR__", "/srv/blog",
		"__CONFIG_IMAGE__", "ghcr.io/you/blog-config",
		"__PROXY_CONTAINER__", "komizo-proxy",
		"__ROUTES_DIR__", "/srv/_proxy/routes",
	)
	for _, c := range []struct{ name, start, end string }{
		{"deploy-<app>", `cat > "$DEPLOY_BIN.tmp" <<'KOMIZO_DEPLOY_EOF'`, "KOMIZO_DEPLOY_EOF"},
		{"set-secret-<app>", `cat > "$SECRET_BIN.tmp" <<'KOMIZO_SECRET_EOF'`, "KOMIZO_SECRET_EOF"},
	} {
		body := between(t, scripts.AlpineScript, c.start, c.end)
		out := subs.Replace(body)
		if strings.Contains(out, "__") && strings.Contains(out, "__APP") {
			t.Errorf("%s still has placeholders after substitution", c.name)
		}
		shellCheck(t, c.name, out)
	}
}

// TestTheDeployScriptCarriesItsInstallTimeValues is the other half: valid shell
// that substituted nothing would be a script addressing an app called
// __APP_NAME__.
func TestTheDeployScriptCarriesItsInstallTimeValues(t *testing.T) {
	body := between(t, scripts.AlpineScript,
		`cat > "$DEPLOY_BIN.tmp" <<'KOMIZO_DEPLOY_EOF'`, "KOMIZO_DEPLOY_EOF")
	for _, want := range []string{
		"__APP_NAME__", "__APP_DIR__", "__CONFIG_IMAGE__", "__ROUTES_DIR__",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the deploy template no longer mentions %s -- if it moved, "+
				"the sed that substitutes it has to move too", want)
		}
	}
	// Every placeholder the template uses must be one alpine.sh substitutes,
	// or it reaches the box verbatim.
	for _, ph := range placeholders(body) {
		if !strings.Contains(scripts.AlpineScript, "s|"+ph+"|") {
			t.Errorf("%s is used in the deploy template but never substituted", ph)
		}
	}
}

// The one input alpine.sh takes that has THREE states rather than two: names
// given, names not mentioned, and no names at all. The middle one is what a
// config-image change means by saying nothing, and it is why the third needs a
// variable of its own.
//
// Run rather than read. Every check below happens before the script asks
// whether it is root, so this exercises the real branch on any machine -- which
// is the point: a fail-safe that is only asserted to exist in the text is a
// fail-safe nobody has seen fail.
func TestSayingThereAreNoNamesIsNotTheSameAsSayingNothing(t *testing.T) {
	needs(t, "sh")
	run := func(env ...string) (string, error) {
		cmd := exec.Command("sh", "-s")
		cmd.Stdin = strings.NewReader(scripts.AlpineScript)
		cmd.Env = append([]string{"APP_NAME=blog", "CONFIG_IMAGE=ghcr.io/you/blog-config",
			"PATH=/usr/bin:/bin"}, env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Both at once says two different things, and guessing which one was meant
	// is how an app silently loses the names its repo pins.
	out, err := run("CLEAR_KNOWN_AS=1", "KNOWN_AS=blog.example.com")
	if err == nil || !strings.Contains(out, "two different things") {
		t.Errorf("clearing and setting at once should be refused, got %q / %v", out, err)
	}

	// Anything that is not 0 or 1 is a typo, and a typo must not read as "no".
	// KEEP_DATA on the removal script is guarded the same way and for the same
	// reason: the fail-open reading of a misspelt flag is the destructive one.
	out, err = run("CLEAR_KNOWN_AS=ture")
	if err == nil || !strings.Contains(out, "CLEAR_KNOWN_AS must be 0 or 1") {
		t.Errorf("a misspelt flag should be refused, got %q / %v", out, err)
	}

	// And the ordinary cases get past this block entirely -- they fail later, at
	// the root check, which is as far as this test can go.
	for _, e := range []string{"CLEAR_KNOWN_AS=1", "KNOWN_AS=blog.example.com", "CLEAR_KNOWN_AS=0"} {
		if out, _ := run(e); strings.Contains(out, "CLEAR_KNOWN_AS") {
			t.Errorf("%s should be accepted, got %q", e, out)
		}
	}
}

func placeholders(s string) []string {
	var out []string
	seen := map[string]bool{}
	for {
		i := strings.Index(s, "__")
		if i < 0 {
			return out
		}
		rest := s[i+2:]
		j := strings.Index(rest, "__")
		if j < 0 {
			return out
		}
		name := "__" + rest[:j] + "__"
		if !seen[name] && strings.Trim(rest[:j], "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") == "" && rest[:j] != "" {
			seen[name] = true
			out = append(out, name)
		}
		s = rest[j+2:]
	}
}

func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("could not find %q -- the template markers moved", start)
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, "\n"+end)
	if j < 0 {
		t.Fatalf("could not find the end of %q", start)
	}
	return rest[:j]
}
