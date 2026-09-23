package box

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The ask endpoint, over the wire: preview names get a certificate, and
// everything else -- apex, other subdomains, other domains, lookalikes, and
// a request that names nothing -- is refused.
func TestTheAskEndpointScopesApprovals(t *testing.T) {
	ts := httptest.NewServer(PreviewAskHandler(PreviewKnob{Domain: "preview.gdam.dev"}))
	defer ts.Close()

	for _, tc := range []struct {
		host string
		want int
	}{
		{"pr-1.preview.gdam.dev", http.StatusOK},
		{"pr-123-api.preview.gdam.dev", http.StatusOK},
		{"preview.gdam.dev", http.StatusForbidden},
		{"www.preview.gdam.dev", http.StatusForbidden},
		{"pr-x.preview.gdam.dev", http.StatusForbidden},
		{"gdam.dev", http.StatusForbidden},
		{"pr-1.preview.gdam.dev.evil.com", http.StatusForbidden},
		{"", http.StatusForbidden},
	} {
		res, err := http.Get(ts.URL + "/ask?domain=" + tc.host) //nolint:gosec // the test's own listener
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Errorf("ask for %q = %d, want %d", tc.host, res.StatusCode, tc.want)
		}
	}
}

// The ask approves the UNION: pr-<N> under the default domain AND under
// every configured DOMAIN.<app>, and refuses anything else -- an
// unconfigured domain, an apex, a non-pr host under a configured one.
func TestTheAskEndpointApprovesTheUnionOfAppDomains(t *testing.T) {
	knob, _ := ParsePreviewKnob("DOMAIN=preview.gdam.dev\nDOMAIN.avior=preview.avior.studio\nDOMAIN.biome=preview.biome.example\n")
	ts := httptest.NewServer(PreviewAskHandler(knob))
	defer ts.Close()

	for _, tc := range []struct {
		host string
		want int
	}{
		{"pr-1.preview.gdam.dev", http.StatusOK},     // the default
		{"pr-1.preview.avior.studio", http.StatusOK}, // configured app
		{"pr-12-api.preview.avior.studio", http.StatusOK},
		{"pr-1.preview.biome.example", http.StatusOK}, // the other configured app
		{"pr-1.preview.unconfigured.dev", http.StatusForbidden},
		{"preview.avior.studio", http.StatusForbidden}, // an apex is not a preview
		{"www.preview.avior.studio", http.StatusForbidden},
		{"pr-x.preview.avior.studio", http.StatusForbidden},
		{"pr-1.preview.avior.studio.evil.com", http.StatusForbidden},
	} {
		res, err := http.Get(ts.URL + "/ask?domain=" + tc.host) //nolint:gosec // the test's own listener
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Errorf("ask for %q = %d, want %d", tc.host, res.StatusCode, tc.want)
		}
	}
}
