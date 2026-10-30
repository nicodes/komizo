package workload

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// StaticLimits belongs to the protected host policy, never the public archive.
// Zero values retain the conservative public-tree envelope.
type StaticLimits struct {
	MaxBytes     int64 `json:"max_bytes,omitempty"`
	MaxFileBytes int64 `json:"max_file_bytes,omitempty"`
}

const StaticBytesCeiling int64 = 1 << 30
const StaticFileBytesCeiling int64 = 128 << 20

func StaticBounds(limits StaticLimits) (total, file int64, err error) {
	total, file = limits.MaxBytes, limits.MaxFileBytes
	if total == 0 {
		total = StaticMaxBytes
	}
	if file == 0 {
		file = StaticMaxFileBytes
	}
	if total < 1 || total > StaticBytesCeiling || file < 1 || file > StaticFileBytesCeiling || file > total {
		return 0, 0, errors.New("static archive bounds exceed the protected envelope")
	}
	return total, file, nil
}

// StaticServingOptions describes HTTP behavior independently of an SDK or
// export layout. It cannot select upstreams, filesystem roots or plugins.
type StaticServingOptions struct {
	Fallbacks          []string           `json:"fallbacks,omitempty"`
	DenyPaths          []string           `json:"deny_paths,omitempty"`
	Headers            map[string]string  `json:"headers,omitempty"`
	HeaderRules        []StaticHeaderRule `json:"header_rules,omitempty"`
	Precompressed      []string           `json:"precompressed,omitempty"`
	Encode             []string           `json:"encode,omitempty"`
	EncodeContentTypes []string           `json:"encode_content_types,omitempty"`
}

type StaticHeaderRule struct {
	Paths        []string          `json:"paths,omitempty"`
	ExceptPaths  []string          `json:"except_paths,omitempty"`
	PathRegexp   string            `json:"path_regexp,omitempty"`
	Methods      []string          `json:"methods,omitempty"`
	ExistingFile bool              `json:"existing_file,omitempty"`
	Headers      map[string]string `json:"headers"`
}

var staticHeaderName = regexp.MustCompile("^[A-Za-z][A-Za-z0-9-]{0,99}$")
var staticRegexpRepetition = regexp.MustCompile("\\{[0-9]+(?:,[0-9]*)?\\}")

func staticText(value string, max int) bool {
	if value == "" || len(value) > max || strings.ContainsAny(value, "{}") {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func staticPatterns(values []string) bool {
	if len(values) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !staticText(value, 1024) || strings.ContainsAny(value, " \t\\\"") || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func staticHeaders(headers map[string]string) bool {
	if len(headers) > 32 {
		return false
	}
	seen := map[string]bool{}
	for name, value := range headers {
		lower := strings.ToLower(name)
		if !staticHeaderName.MatchString(name) || !staticText(value, 4096) || seen[lower] ||
			lower == "x-komizo-revision" || lower == "content-length" || lower == "transfer-encoding" || lower == "connection" {
			return false
		}
		seen[lower] = true
	}
	return true
}

func (s StaticServingOptions) Check() error {
	if len(s.Fallbacks) > 16 || !staticPatterns(s.DenyPaths) || !staticHeaders(s.Headers) || len(s.HeaderRules) > 32 {
		return errors.New("invalid bounded static serving settings")
	}
	for _, value := range s.Fallbacks {
		path := strings.ReplaceAll(value, "{path}", "/request")
		if !staticPatterns([]string{path}) || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return errors.New("invalid static fallback path")
		}
	}
	for _, rule := range s.HeaderRules {
		if !staticPatterns(rule.Paths) || !staticPatterns(rule.ExceptPaths) || len(rule.Headers) == 0 || !staticHeaders(rule.Headers) ||
			len(rule.Methods) > 8 || len(rule.Paths)+len(rule.ExceptPaths)+len(rule.PathRegexp)+len(rule.Methods) == 0 && !rule.ExistingFile {
			return errors.New("invalid static header selector")
		}
		for _, method := range rule.Methods {
			if method != "GET" && method != "HEAD" && method != "OPTIONS" {
				return errors.New("unsupported static request method")
			}
		}
		if rule.PathRegexp != "" {
			// RE2 repetition braces are data, unlike response-header placeholders.
			if len(rule.PathRegexp) > 1024 || strings.ContainsAny(rule.PathRegexp, "\x00\r\n") || strings.ContainsAny(staticRegexpRepetition.ReplaceAllString(rule.PathRegexp, ""), "{}") {
				return errors.New("invalid static path expression")
			}
			if _, err := regexp.Compile(rule.PathRegexp); err != nil {
				return errors.New("invalid static path expression")
			}
		}
	}
	for _, values := range [][]string{s.Precompressed, s.Encode} {
		if len(values) > 3 {
			return errors.New("too many static encoders")
		}
		seen := map[string]bool{}
		for _, value := range values {
			if (value != "br" && value != "gzip" && value != "zstd") || seen[value] {
				return errors.New("unsupported or duplicate static encoding")
			}
			seen[value] = true
		}
	}
	// The stock proxy encodes gzip/zstd; Brotli is served from sidecars.
	for _, value := range s.Encode {
		if value == "br" {
			return errors.New("Brotli requires precompressed sidecars")
		}
	}
	if len(s.EncodeContentTypes) > 0 && len(s.Encode) == 0 || !staticPatterns(s.EncodeContentTypes) {
		return errors.New("invalid static compression selectors")
	}
	return nil
}

func staticWords(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = strconv.Quote(value)
	}
	return strings.Join(quoted, " ")
}

func staticHeaderBlock(b *strings.Builder, selector string, headers map[string]string) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, name := range keys {
		fmt.Fprintf(b, "\t\theader %s%s %s\n", selector, name, strconv.Quote(headers[name]))
	}
}

func staticServingRoute(app, revision string, s StaticServingOptions) string {
	var b strings.Builder
	// Explicit ordering prevents fallback rewrites from bypassing denied paths.
	fmt.Fprintf(&b, "\troute {\n\t\troot * %s/%s/%s\n", StaticContainerRoot, app, revision)
	staticHeaderBlock(&b, "", s.Headers)
	for i, rule := range s.HeaderRules {
		name := fmt.Sprintf("%s_header_%d", app, i)
		fmt.Fprintf(&b, "\t\t@%s {\n", name)
		if len(rule.Paths) > 0 {
			fmt.Fprintf(&b, "\t\t\tpath %s\n", staticWords(rule.Paths))
		}
		if len(rule.ExceptPaths) > 0 {
			fmt.Fprintf(&b, "\t\t\tnot path %s\n", staticWords(rule.ExceptPaths))
		}
		if rule.PathRegexp != "" {
			fmt.Fprintf(&b, "\t\t\tpath_regexp %s %s\n", name, strconv.Quote(rule.PathRegexp))
		}
		if len(rule.Methods) > 0 {
			fmt.Fprintf(&b, "\t\t\tmethod %s\n", strings.Join(rule.Methods, " "))
		}
		if rule.ExistingFile {
			b.WriteString("\t\t\tfile {path}\n")
		}
		b.WriteString("\t\t}\n")
		staticHeaderBlock(&b, "@"+name+" ", rule.Headers)
	}
	if len(s.DenyPaths) > 0 {
		fmt.Fprintf(&b, "\t\t@%s_denied path %s\n\t\trespond @%s_denied 404\n", app, staticWords(s.DenyPaths), app)
	}
	if len(s.Encode) > 0 {
		fmt.Fprintf(&b, "\t\tencode %s", strings.Join(s.Encode, " "))
		if len(s.EncodeContentTypes) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteString(" {\n\t\t\tmatch {\n")
			for _, value := range s.EncodeContentTypes {
				fmt.Fprintf(&b, "\t\t\t\theader Content-Type %s\n", strconv.Quote(value))
			}
			b.WriteString("\t\t\t}\n\t\t}\n")
		}
	}
	if len(s.Fallbacks) > 0 {
		fmt.Fprintf(&b, "\t\ttry_files %s\n", staticWords(s.Fallbacks))
	}
	if len(s.Precompressed) == 0 {
		b.WriteString("\t\tfile_server\n")
	} else {
		fmt.Fprintf(&b, "\t\tfile_server {\n\t\t\tprecompressed %s\n\t\t}\n", strings.Join(s.Precompressed, " "))
	}
	b.WriteString("\t}\n")
	return b.String()
}
