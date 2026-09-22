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
	ts := httptest.NewServer(PreviewAskHandler("preview.gdam.dev"))
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
