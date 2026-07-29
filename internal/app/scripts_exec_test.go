package app

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// The scripts this package ships are shell and awk held in Go strings, and
// nothing here used to RUN any of them.
//
// That is not a gap in coverage, it is the gap that mattered. The request-counts
// awk carried three defects at once -- a range filter that referenced two
// variables nobody had defined, and a span record built from two more that were
// never assigned -- and the test named for that behaviour asserted the numbers
// appeared in the script TEXT and then fed a hand-written line to the parser.
// Every assertion passed against a program that could not do what it said.
//
// So: syntax-check everything that is generated, and execute the part that
// computes.

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

func TestEveryGeneratedScriptIsValidShell(t *testing.T) {
	needs(t, "sh")
	now := int64(1753700400)
	for _, c := range []struct{ name, script string }{
		{"inventory", inventoryScript},
		{"metrics", metricsScript(timeRange{from: now - 3600, to: now})},
		{"sampler", samplerFile()},
		{"sampler installer", samplerScript()},
		{"storage", storageScript("blog")},
		{"system log", systemLogScript(timeRange{from: now - 3600, to: now})},
	} {
		shellCheck(t, c.name, c.script)
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

// --- the awk that counts requests ------------------------------------------

// awkProgram pulls the awk out of the generated script, so what runs here is
// the text that ships rather than a copy of it.
func awkProgram(t *testing.T, script string) string {
	t.Helper()
	const marker = "| awk -v from="
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatal("could not find the awk in the metrics script")
	}
	j := strings.Index(script[i:], "'")
	if j < 0 {
		t.Fatal("the awk program is not quoted as expected")
	}
	start := i + j + 1
	k := strings.LastIndex(script, "'")
	if k <= start {
		t.Fatal("could not find the end of the awk program")
	}
	return script[start:k]
}

func runAwk(t *testing.T, prog string, from, to int64, stdin string) string {
	t.Helper()
	cmd := exec.Command("awk",
		"-v", "from="+strconv.FormatInt(from, 10),
		"-v", "to="+strconv.FormatInt(to, 10), prog)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("awk failed: %v\n%s", err, out)
	}
	return string(out)
}

// accessLine is one Caddy access-log record, in the shape the generated site
// blocks actually write: JSON, with the three fields the awk pulls by pattern.
func accessLine(ts int64, host string, status int) string {
	return fmt.Sprintf(`{"level":"info","ts":%d.123,"logger":"http.log.access",`+
		`"msg":"handled request","request":{"remote_ip":"1.2.3.4","host":%q,`+
		`"method":"GET","uri":"/"},"status":%d,"size":12}`, ts, host, status)
}

// The range is applied ON THE HOST, which is the claim the docstring makes and
// which was false: from and to were passed to the awk and then never mentioned
// in it, so every poll counted and shipped the whole four-megabyte tail.
func TestTheAwkAppliesTheRangeItIsGiven(t *testing.T) {
	needs(t, "awk")
	prog := awkProgram(t, metricsScript(timeRange{from: 0, to: 0}))

	const minute = 1753700400
	in := strings.Join([]string{
		"MAP\tblog.example.com\tblog\tweb",
		accessLine(minute+30, "blog.example.com", 200),   // inside
		accessLine(minute-600, "blog.example.com", 200),  // hours older, outside
		accessLine(minute+9000, "blog.example.com", 500), // later, outside
	}, "\n")

	out := runAwk(t, prog, minute, minute+59, in)

	rows := parseMetrics(out)
	if len(rows) != 1 {
		t.Fatalf("expected one minute in range, got %d: %q", len(rows), out)
	}
	if rows[0].minute != minute || rows[0].c2 != 1 {
		t.Errorf("expected one 2xx at %d, got %+v", minute, rows[0])
	}
	if rows[0].c5 != 0 {
		t.Errorf("a 5xx outside the range was counted: %+v", rows[0])
	}
}

// And the span is measured over EVERYTHING the tail holds, including the lines
// the range excludes -- they are the only evidence of how far back the log
// goes, which is what tells a chart where to stop drawing zeroes.
func TestTheAwkReportsHowFarBackTheLogGoes(t *testing.T) {
	needs(t, "awk")
	prog := awkProgram(t, metricsScript(timeRange{from: 0, to: 0}))

	const minute = 1753700400
	in := strings.Join([]string{
		"MAP\tblog.example.com\tblog\tweb",
		accessLine(minute-3600, "blog.example.com", 200),
		accessLine(minute+30, "blog.example.com", 200),
	}, "\n")

	out := runAwk(t, prog, minute, minute+59, in)

	span, ok := parseMetricSpan(out)
	if !ok {
		t.Fatalf("no mspan record: %q", out)
	}
	if span.from > minute-3600 {
		t.Errorf("mspan should reach the oldest line in the tail (%d), got %d",
			minute-3600, span.from)
	}
	if span.to < minute+30 {
		t.Errorf("mspan should reach the newest line (%d), got %d", minute+30, span.to)
	}
}

// A hostname that matches no exact entry falls back to the wildcard its parent
// would have claimed, which is how a preview domain is attributed at all.
func TestTheAwkAttributesWildcardHostnames(t *testing.T) {
	needs(t, "awk")
	prog := awkProgram(t, metricsScript(timeRange{from: 0, to: 0}))

	const minute = 1753700400
	in := strings.Join([]string{
		"MAP\t*.preview.example.com\tblog\tweb",
		accessLine(minute+10, "pr-42.preview.example.com", 200),
		accessLine(minute+20, "somebody-elses.example.net", 200),
	}, "\n")

	rows := parseMetrics(runAwk(t, prog, minute, minute+59, in))
	if len(rows) != 1 {
		t.Fatalf("expected the wildcard to claim one row, got %d", len(rows))
	}
	if rows[0].app != "blog" || rows[0].c2 != 1 {
		t.Errorf("expected one 2xx for blog, got %+v", rows[0])
	}
}
